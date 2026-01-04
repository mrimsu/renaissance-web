<?php
declare(strict_types=1);

namespace App\Auth;

use DateTime;
use Emails;
use Nette;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\AuthenticationException;
use Nette\Database\Explorer;
use Nette\Database\Table\Selection;

use App\Auth\User;
use App\Auth\UserIdentity;
use Nette\Utils\Validators;

final class Auth implements IAuthenticator
{
    use Nette\SmartObject;

    private Explorer $db;

    public function __construct(Explorer $db)
    {
        $this->db = $db;
    }

    public function authenticate($args)
    {
        [$email, $password] = $args;

        if (strpos($email, "@") !== false) {
            [$login, $domain] = explode("@", $email, 2);
        } else {
            throw new AuthenticationException("Неверная виртуальная почта");
        }

        $row = $this->db
            ->table('user')
            ->where('login', $login)
            ->where('domain', $domain)
            ->fetch();

        // obfuscation
        if(!$row) 
            throw new AuthenticationException("Неверная виртуальная почта или пароль");

        // don't worry about md5, it automatically generates an passwd for usr
        if(hash_equals($row->passwd, md5($password))) {
            return new UserIdentity($row->id);
        } else { 
            throw new AuthenticationException("Неверная виртуальная почта или пароль");
        }
    }

    public function add($args)
    {
        [$name, $surname, $real_email, $username, $domain, $sex, $birthday, $nickname, $place] = $args;
        // проверка полей, не пусты ли они
        foreach([$name, $surname, $real_email, $username, $nickname] as $value){
            if(Validators::is($value, 'none'))
                throw new AuthenticationException("Не все поля заполнены");
        }
        // проверка даты рождения
        $d = DateTime::createFromFormat("Y-m-d", $birthday);
        if(!$d && $d->format("Y-m-d") == $birthday)
            throw new AuthenticationException("Неверный формат даты рождения. Формат: ГГГГ-ММ-ДД");
        // проверка возраста (а то вдруг чел уже сдох или не родился даже)
        $current_date = date('Y-m-d');
        $birth_timestamp = strtotime($birthday);
        $current_timestamp = strtotime($current_date);
        $diff_seconds = $current_timestamp - $birth_timestamp;
        $age_years = $diff_seconds / (60 * 60 * 24 * 365.25);
        $age_years = round($age_years);
        if($age_years < 0 || $age_years > 100)
            throw new AuthenticationException("Неверный формат даты рождения. Формат: ГГГГ-ММ-ДД");
        // тест на небинарность (проверка секса (пола))
        if($sex != 1 && $sex != 2)
            throw new AuthenticationException("Неверный пол");
        // проверяем домен
        $allowed_domains = ["mail.ru", "list.ru", "bk.ru", "inbox.ru"];
        if(!in_array($domain, $allowed_domains))
            throw new AuthenticationException("Неверный виртуальный домен");
        // логин
        if (!preg_match('/^[a-zA-Z0-9\-_.]+$/', $username))
            throw new AuthenticationException("Виртуальная почта должна содержать латинские буквы, цифры, нижнее подчёркивание, тире и/или точку");
        // проверка почты и ника
        if($this->db->table("user")->where("real_email", $real_email)->count() > 0)
            throw new AuthenticationException("Пользователь с такой электронной почтой уже существует. Попробуйте восстановить пароль, используя вашу электронную почту");
        if($this->db->table("user")->where("login", $username)->count() > 0)
            throw new AuthenticationException("Пользователь с таким логином (виртуальной почтой) уже существует. Попробуйте зарегистрировать аккаунт с другой виртуальной почтой");
        // если всё оке то мы регаем пользователя (с cгенерированным паролем) в временную таблицу с пользователями
        $query = $this->db->table("user")->insert([
            "login" => $username,
            "real_email" => $real_email,
            "passwd" => md5(Nette\Utils\Random::generate(16, '0-9a-zA-Z')),
            "domain" => $domain,
            "nick" => $nickname,
            "f_name" => $name,
            "l_name" => $surname,
            "location" => $place,
            "birthday" => $birthday,
            "sex" => $sex
        ]);

        $this->db->table("contact_group")->insert([
            "user_id" => $query->id,
            "name" => "Остальные",
            "idx" => '0'
        ]);
        $this->db->table("contact_group")->insert([
            "user_id" => $query->id,
            "name" => "Родные",
            "idx" => '1'
        ]);
        $this->db->table("contact_group")->insert([
            "user_id" => $query->id,
            "name" => "Друзья",
            "idx" => '2'
        ]);
        $this->db->table("contact_group")->insert([
            "user_id" => $query->id,
            "name" => "Коллеги",
            "idx" => '3'
        ]);
        // верифка по почте
        $code = Nette\Utils\Random::generate(72);
        (new Emails())->send($_SERVER['DOCUMENT_ROOT']."/../app/Emails/email_verification.latte", $real_email, ["nickname" => $nickname, "code" => $code, "host" => (empty($_SERVER['HTTPS']) ? 'http' : 'https')."://$_SERVER[HTTP_HOST]/"]);
        $this->db->table("email_messages")->insert([
            "email_message_type" => "email_verification",
            "email_message_code" => $code,
            "email_message_for" => $query->id
        ]);
    }
}