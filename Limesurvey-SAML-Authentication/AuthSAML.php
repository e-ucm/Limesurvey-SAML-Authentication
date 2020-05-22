<?php

/*
 * LimeSurvey Auhtnetication Plugin for Limesurvey 3.14+
 * Auhtor: Frank Niesten
 * License: GNU General Public License v3.0
 *
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 */

class AuthSAML extends LimeSurvey\PluginManager\AuthPluginBase
{
    protected $storage = 'LimeSurvey\PluginManager\DbStorage';
    protected $ssp = null;

    static protected $description = 'Core: SAML authentication';
    static protected $name = 'SAML';

    protected $settings = array(
        'simplesamlphp_path' => array(
            'type' => 'string',
            'label' => 'Path to the SimpleSAMLphp folder',
            'default' => '/usr/share/simplesamlphp',
        ),
        'simplesamlphp_cookie_session_storage' => array(
            'type' => 'checkbox',
            'label' => 'Does simplesamlphp use cookie as a session storage ?',
            'default' => true,
        ),
        'saml_authsource' => array(
            'type' => 'string',
            'label' => 'SAML authentication source',
            'default' => 'default-sp',
        ),
        'saml_uid_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as username',
            'default' => 'uid',
        ),
        'saml_mail_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as email',
            'default' => 'mail',
        ),
        'saml_name_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as name',
            'default' => 'cn',
        ),
        'auto_create_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto create users',
            'default' => true,
        ),
        'auto_update_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
        'force_saml_login' => array(
            'type' => 'checkbox',
            'label' => 'Force SAML login.',
            'default' => false,
        ),
        'authtype_base' => array(
            'type' => 'string',
            'label' => 'Authtype base to modify the login form. If null, then no modification is done.',
            'default' => 'Authdb',
        ),
        'storage_base' => array(
            'type' => 'string',
            'label' => 'Storage base',
            'default' => 'DbStorage',
        ),
        'logout_redirect' => array(
            'type' => 'string',
            'label' => 'Logout Redirect URL',
            'default' => '/admin',
        ),
        'simplesamlphp_logo_path' => array(
            'type' => 'logo',
            'label' => 'Plugin logo',
            'path' => 'assets/SSO_LOGO.svg',
            'alt' => 'SAML Logo',
            'style' => 'width:128px',
        ),
    );

    public function init() {
        $this->storage = $this->get('storage_base', null, null, $this->settings['storage_base']['default']);

        $this->subscribe('getGlobalBasePermissions');

        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');

        if (!$this->get('force_saml_login', null, null, $this->settings['force_saml_login']['default'])) {
            $this->subscribe('newLoginForm');
        }
    }

    /**
     * Add AuthSAML Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(


            'auth_saml' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use SAML authentication"),
                'description' => gT("Use SAML authentication"),
                'img' => 'usergroup'
            ),
        ));
    }

    public function beforeLogin() {
        $ssp = $this->get_saml_instance();

        $sessionCleanupNeeded = session_status() === PHP_SESSION_ACTIVE;
        $sessionCleanupRequired = $this->get('simplesamlphp_cookie_session_storage', null, null, $this->settings['simplesamlphp_cookie_session_storage']['default']);

        $ssp = $this->get_saml_instance();

        if ($this->get('force_saml_login', null, null, $this->settings['force_saml_login']['default'])) {
            $ssp->requireAuth();
        }

        $isAuthenticated = $ssp->isAuthenticated();

        if ($isAuthenticated) {
            $sUser = $this->getUserName();
            if ($sessionCleanupNeeded && $sessionCleanupRequired) {
                \SimpleSAML\Session::getSessionFromRequest()->cleanup();
            }
            $this->setAuthPlugin();
            $this->newUserSession();
        } else {
            if ($sessionCleanupNeeded && $sessionCleanupRequired) {
                \SimpleSAML\Session::getSessionFromRequest()->cleanup();
            }
        }
    }

    public function afterLogout()
    {
        $ssp = $this->get_saml_instance();

        if ($ssp->isAuthenticated()) {
            $redirect = $this->get('logout_redirect', null, null, $this->settings['logout_redirect']['default']);
            $redirect = Yii::app()->getController()->createUrl($redirect);

            Yii::app()->controller->redirect($ssp->getLogoutUrl($redirect));
            Yii::app()->end();
        }
    }

    public function newLoginForm()
    {
        $authtype_base = $this->get('authtype_base', null, null, $this->settings['authtype_base']['default']);

        $ssp = $this->get_saml_instance();
        $loginUrl = $ssp->getLoginURL();

        $pluginsettings = $this->getPluginSettings(true);
        $imgUrl = $pluginsettings['simplesamlphp_logo_path']['path'];

        if ($authtype_base != null) {
            // This add the login button to the auth_base authentication method
            $this->getEvent()
                ->getContent($authtype_base)
                ->addContent('<center>Click on that button to initiate SAML Login<br>
                    <a href="' . $loginUrl . '" title="SAML Login">
                    <img src="' .$imgUrl . '" width="100px"></a></center><br>
                    ', LimeSurvey\PluginManager\PluginEventContent::PREPEND);
        }

        // This generates the "login form" for this plugin, basically a link to follow.
        $this->getEvent()
            ->getContent($this)
            ->addContent('<center>Click on that button to initiate SAML Login<br>
                <a href="' . $loginUrl . '" title="SAML Login">
                 <img src="' . $imgUrl . '" width="100px"></a></center><br>
                 ');
    }

    public function newUserSession() {

        $ssp = $this->get_saml_instance();

        if ($ssp->isAuthenticated()) {

            $sUser = $this->getUserName();
            $name = $this->getUserCommonName();
            $mail = $this->getUserMail();

            $oUser = $this->api->getUserByName($sUser);

            $auto_create_users = $this->get('auto_create_users', null, null, true);

            if (is_null($oUser) and $auto_create_users) {

                // Create new user
                $oUser = new User;
                $oUser->users_name = $sUser;
                $oUser->setPassword(createPassword());
                $oUser->full_name = $name;
                $oUser->parent_id = 1;
                $oUser->email = $mail;

                if ($oUser->save()) {
                    $permission = new Permission;

                    Permission::model()->setGlobalPermission($oUser->uid, 'auth_saml');

                    $oUser = $this->api->getUserByName($sUser);

                    $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));

                    $this->setAuthSuccess($oUser);
                } else {
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                }
            } elseif (is_null($oUser)) {
                throw new CHttpException(401, gT("We are sorry but you do not have an account."));
            } else {

                // *** Update user ***
                $auto_update_users = $this->get('auto_update_users', null, null, true);

                if ($auto_update_users) {
                    $changes = array (
                        'full_name' => $name,
                        'email' => $mail,
                    );

                    User::model()->updateByPk($oUser->uid, $changes);
                    $oUser = $this->api->getUserByName($sUser);
                }

                $this->setAuthSuccess($oUser);
            }
        }
        $flag = $this->get('simplesamlphp_cookie_session_storage', null, null, true);
        if ($flag){
            $session = SimpleSAML_Session::getSessionFromRequest();
            $session->cleanup();
        }
    }

    /**
     * Initialize SAML authentication
     * @return void
     */
    public function get_saml_instance() {

        if ($this->ssp == null) {

            $simplesamlphp_path = $this->get('simplesamlphp_path', null, null, '/var/www/simplesamlphp');

            require_once($simplesamlphp_path.'/lib/_autoload.php');

            $saml_authsource = $this->get('saml_authsource', null, null, 'limesurvey');

            $this->ssp = new \SimpleSAML\Auth\Simple($saml_authsource);
        }

        return $this->ssp;
    }

    /**
     * Get Userdata from SAML Attributes
     * @return void
     */
    public function getUserName() {

        if ($this->_username == null) {
            $username = $this->getUserNameAttribute();
            if ($username !== false) {
                $this->setUsername($username);
            }
        }

        return $this->_username;
    }

    public function getUserNameAttribute()
    {
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_uid_mapping = $this->get('saml_uid_mapping', null, null, 'uid');
            if (array_key_exists($saml_uid_mapping, $attributes) && !empty($attributes[$saml_uid_mapping])) {
                $username = $attributes[$saml_uid_mapping][0];
                return $username;
            }
        }
        return false;
    }

    public function getUserCommonName() {

        $name = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_name_mapping = $this->get('saml_name_mapping', null, null, 'cn');
            if (array_key_exists($saml_name_mapping , $attributes) && !empty($attributes[$saml_name_mapping])) {
                $name = $attributes[$saml_name_mapping][0];
            }
        }

        return $name;
    }

    public function getUserMail() {

        $mail = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_mail_mapping = $this->get('saml_mail_mapping', null, null, 'mail');
            if (array_key_exists($saml_mail_mapping , $attributes) && !empty($attributes[$saml_mail_mapping])) {
                $mail = $attributes[$saml_mail_mapping][0];
            }
        }

        return $mail;
    }
}
