<?php

declare(strict_types=1);

namespace App\UI\Authentication;

use Emails;
use Nette;
use App\Presenter as CustomPresenter;
use App\Auth\Auth;
use DateTime;
use Nette\Utils\Validators;
use Nette\Utils\Image;
use Nette\Utils\Random;

final class AuthenticationPresenter extends CustomPresenter
{
    public function renderLogin()
    {
        if ($this->getUser()->isLoggedIn()) {
            $this->redirect('Home:default');
        }

        if ($this->getHttpRequest()->getMethod() === 'POST')
        {
            try {
                $this->getUser()->login($this->getHttpRequest()->getPost('email'), $this->getHttpRequest()->getPost('password'));
                $this->redirect('Home:default');
            } catch (Nette\Security\AuthenticationException $e) {
                $this->flashMessage('Ошибка: ' . $e->getMessage(), 'error');
                $this->redirect('this');
            }
        }
    }

    public function renderVerification()
    {
        $query = $this->db->table("email_messages")->where(["email_message_code" => $_GET['code']]);
        if($query->count() > 0){
            $email_data = $query->fetch();
            $user = $this->db->table("user")->get($email_data->email_message_for);
            $this->template->email_message_type = $email_data->email_message_type;
            if($email_data->email_message_type == "email_change"){
                // меняем почту пользователю и делаем его активным (на случай если у него не было вообще почты)
                $user->update([
                    "real_email" => $email_data->email_message_data,
                    "activated" => 1
                ]);
            }else{
                if ($this->getUser()->isLoggedIn()) {
                    $this->redirect('Home:default');
                }
                // меняем пароль пользователю, делаем его активным и удаляем запись о верифке почты
                $password = Nette\Utils\Random::generate(16, '0-9a-zA-Z');
                $user->update([
                    "passwd" => md5($password),
                    "activated" => 1
                ]);
                
                $this->template->password = $password;

                (new Emails())->send($_SERVER['DOCUMENT_ROOT']."/../app/Emails/password.latte", $user->real_email, ["nickname" => $user->nick, "vmail" => $user->login . "@" . $user->domain, "reset" => $email_data->email_message_type == "password_reset", "password" => $password, "host" => (empty($_SERVER['HTTPS']) ? 'http' : 'https')."://$_SERVER[HTTP_HOST]/"]);
            }
            $query->delete();
        }else{
            $this->flashMessage('Ошибка: Просроченная верификация', 'error');
            $this->redirect('Home:default');
        }
    }

    public function renderLogout()
    {
        $this->getUser()->logout();
        $this->redirect('Home:default');
    }

    public function renderRegistration()
    {
        if ($this->getUser()->isLoggedIn()) {
            $this->redirect('Home:default');
        }
        $this->template->registered = false;
        if ($this->getHttpRequest()->getMethod() === 'POST')
        {
            try {
                (new Auth($this->db))->add([
                    $this->getHttpRequest()->getPost('name'),
                    $this->getHttpRequest()->getPost('surname'),
                    $this->getHttpRequest()->getPost('real_email'),
                    $this->getHttpRequest()->getPost('username'),
                    $this->getHttpRequest()->getPost('domain'),
                    $this->getHttpRequest()->getPost('sex'),
                    $this->getHttpRequest()->getPost('birthday'),
                    $this->getHttpRequest()->getPost('nickname'),
                    $this->getHttpRequest()->getPost('place')
                ]);
                $this->template->registered = true;
            } catch (Nette\Security\AuthenticationException $e) {
                $this->flashMessage('Ошибка: ' . $e->getMessage(), 'error');
                $this->redirect('this');
            }
        }
    }

    public function renderPasswordReset()
    {
        if ($this->getUser()->isLoggedIn()) {
            $this->redirect('Home:default');
        }
        if ($this->getHttpRequest()->getMethod() === 'POST')
        {
            // проверка введена ли почта
            if(Validators::is($this->getHttpRequest()->getPost('real_email'), "none")){
                $this->flashMessage('Введите электронную почту!', 'info');
                $this->redirect('this');
                die;
            }

            $user = $this->db->table("user")->where("real_email", $this->getHttpRequest()->getPost('real_email'));
            if($user->count() > 0){
                // если пользователь существует то отправляем ему письмо
                $user_data = $user->fetch();
                $code = Nette\Utils\Random::generate(72);
                (new Emails())->send($_SERVER['DOCUMENT_ROOT']."/../app/Emails/password_reset.latte", $this->getHttpRequest()->getPost('real_email'), ["nickname" => $user_data->nick, "code" => $code, "host" => (empty($_SERVER['HTTPS']) ? 'http' : 'https')."://$_SERVER[HTTP_HOST]/"]);
                $this->db->table("email_messages")->insert([
                    "email_message_type" => "password_reset",
                    "email_message_code" => $code,
                    "email_message_for" => $user_data->id
                ]);
            }

            $this->flashMessage('Если ваша учётная запись есть в нашей базе данных, то мы отправили вам письмо с ссылкой подтверждения для сброса пароля', 'info');
            $this->redirect('this');
        }
    }

    public function renderEditProfile()
    {
        if (!$this->getUser()->isLoggedIn()) {
            $this->flashMessage('Ошибка: Вам нужно сначала авторизоваться', 'error');
            $this->redirect('Home:default');
        }

        $id = $this->getUser()->getId();
        $user = $this->db->table('user')->get($id);
        $this->template->user_data = $user;
        $this->template->obraz_domain = mrim_obraz_url;
        
        if ($this->getHttpRequest()->getMethod() === 'POST')
        {

            $vals = $this->getHttpRequest()->getPost();
            $error = '';
            // проверка вводимости
            foreach([$vals['name'], $vals['nickname']] as $value){
                if(Validators::is($value, 'none'))
                    $error = "Не все поля заполнены";
            }

            if (Validators::is($vals['real_email'], 'none') && email_enabled) {
                $error = "Не введена электронная почта";
            }
            // проверка даты рождения
            $d = DateTime::createFromFormat("Y-m-d", $vals['birthday']);
            if(!$d && $d->format("Y-m-d") == $vals['birthday'])
                $error = ($error != "" ? "$error; " : "")."Неверный формат даты рождения";
            // проверка возраста (а то вдруг чел уже сдох или не родился даже)
            $current_date = date('Y-m-d');
            $birth_timestamp = strtotime($vals['birthday']);
            $current_timestamp = strtotime($current_date);
            $diff_seconds = $current_timestamp - $birth_timestamp;
            $age_years = $diff_seconds / (60 * 60 * 24 * 365.25);
            $age_years = round($age_years);
            if($age_years < 0 || $age_years > 100)
                $error = ($error != "" ? "$error; " : "")."Неверный формат даты рождения";
            if($error != ''){
                $this->flashMessage("Ошибка: $error", 'error');
                $this->redirect('this');
                die;
            }
            // обновление строки
            $user->update([
                'f_name'     => $vals['name'],
                'l_name'     => $vals['surname'],
                'sex'        => $vals['sex'] == 2 ? 2 : 1,
                'birthday'   => $vals['birthday'],
                'nick'       => $vals['nickname'],
                'location'   => $vals['place'],
            ]);

            // Handle avatar upload
            $avatarFile = $this->getHttpRequest()->getFile('obraz');
            if ($avatarFile && $avatarFile->isOk()) {
                // Validate file type
                $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                if (in_array($avatarFile->getContentType(), $allowedTypes)) {
                    try {
                        // Create avatars directory if it doesn't exist
                        $avatarsPath = constant('avatars_path');
                        if (!is_dir($avatarsPath)) {
                            mkdir($avatarsPath, 0755, true);
                        }
                        
                        // Generate random filename
                        $filename = Random::generate(20) . '.jpg';
                        $filePath = $avatarsPath . '/' . $filename;
                        
                        // Convert and save image as JPG
                        $image = Image::fromFile($avatarFile->getTemporaryFile());
                        $image->resize(500, null, Image::ShrinkOnly);
                        $image->sharpen();
                        $image->save($filePath, 85, Image::JPEG);
                        
                        // Update user's avatar in database
                        $user->update(['avatar' => $filename]);
                    } catch (\Exception $e) {
                        $this->flashMessage('Ошибка при загрузке аватара: ' . $e->getMessage(), 'error');
                    }
                } else {
                    $this->flashMessage('Неверный формат файла. Разрешены только JPG, PNG и GIF.', 'error');
                }
            }

            if($vals['real_email'] != $user->real_email){
                $code = Nette\Utils\Random::generate(72);
                (new Emails())->send($_SERVER['DOCUMENT_ROOT']."/../app/Emails/email_change.latte", $this->getHttpRequest()->getPost('real_email'), ["nickname" => $user->nick, "code" => $code, "host" => (empty($_SERVER['HTTPS']) ? 'http' : 'https')."://$_SERVER[HTTP_HOST]/"]);
                $this->db->table("email_messages")->insert([
                    "email_message_type" => "email_change",
                    "email_message_code" => $code,
                    "email_message_for" => $user->id,
                    "email_message_data" => $vals['real_email']
                ]);
            }

            $this->flashMessage($vals['real_email'] != $user->real_email ? "Анкета сохранена, но необходимо подтвердить вашу новую электронную почту для её смены (отправлено письмо с ссылкой для подтверждения)" : "Анкета сохранена", 'success');
            $this->redirect('this');
        }
    }
}
