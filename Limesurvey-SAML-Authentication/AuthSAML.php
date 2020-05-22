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
        $this->subscribe('beforeHasPermission');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');

        if (!$this->get('force_saml_login', null, null, $this->settings['force_saml_login']['default'])) {
            $this->subscribe('newLoginForm');
        }

        $this->subscribe('beforeActivate');
    }

    public function beforeActivate()
    {
        if ( $this->get_saml_instance() === null ) {
            $event = $this->getEvent();
            $event->set('success', false);
            $event->set('message', gT("SAML authentication failed: Simplesamlphp installation not available."));
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

    /**
     * Validation of AuthPermission (for super-admin only)
     * @return void
     */
    public function beforeHasPermission()
    {
        $oEvent = $this->getEvent();
        if ($oEvent->get('sEntityName') != 'global' || $oEvent->get('sPermission') != 'auth_saml' || $oEvent->get('sCRUD') != 'read') {
            return;
        }
        $iUserId = Permission::getUserId($oEvent->get('iUserID'));
        if ($iUserId == 1) {
            $oEvent->set('bPermission', (bool) $this->get('allowInitialUser'));
        }
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

            $this->setUsername($sUser);
            $this->setAuthPlugin();
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

    public function newUserSession()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        // Do nothing if this user is not AuthSAML type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != get_class($this)) {
            $this->log(__METHOD__.' - Authentication not managed by this plugin', \CLogger::LEVEL_TRACE);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        /* unsubscribe from beforeHasPermission, else current event will be modified during check permissions */
        $this->unsubscribe('beforeHasPermission');

        $ssp = $this->get_saml_instance();
        $isAuthenticated = $ssp->isAuthenticated();

        if (! $isAuthenticated) {
            $sessionCleanupRequired = $this->get('simplesamlphp_cookie_session_storage', null, null, $this->settings['simplesamlphp_cookie_session_storage']['default']);
            if ($sessionCleanupRequired){
                \SimpleSAML\Session::getSessionFromRequest()->cleanup();
            }
            $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            $this->log(__METHOD__.' - ERROR: User not authenticated, but was expected', \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        $sUser = $this->getUserName();
        $name = $this->getUserCommonName();
        $mail = $this->getUserMail();
        $usergroup = $this->getUserGroup();

        $sessionCleanupRequired = $this->get('simplesamlphp_cookie_session_storage', null, null, $this->settings['simplesamlphp_cookie_session_storage']['default']);
        if ($sessionCleanupRequired){
            \SimpleSAML\Session::getSessionFromRequest()->cleanup();
        }


        // Get LS user
        $oUser = $this->api->getUserByName($sUser);

        if (is_null($oUser)) {
            $auto_create_users = $this->get('auto_create_users', null, null, true);
            if ($auto_create_users) {
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

                    $this->log(__METHOD__.' - User created: '.$oUser->uid, \CLogger::LEVEL_INFO);
                } else {
                    $this->log(__METHOD__.' - ERROR: Could not add the user: '.$oUser->uid, \CLogger::LEVEL_ERROR);
                    $this->setAuthFailure(self::ERROR_NOT_ADDED);
                }
            } else {
                $this->log(__METHOD__.' - ERROR: User creation not allowed: '.$oUser->uid, \CLogger::LEVEL_ERROR);
                $this->setAuthFailure(self::ERROR_NOT_ADDED, gT("We are sorry but you do not have an account."));
            }
        } else {

            // If user cannot login via SAML: setAuthFailure
            if (($oUser->uid == 1 && !$this->get('allowInitialUser'))
                || !Permission::model()->hasGlobalPermission('auth_saml', 'read', $oUser->uid))
            {
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('SAML authentication method is not allowed for this user'));
                return;
            }

            // *** Update user ***
            $auto_update_users = $this->get('auto_update_users', null, null, $this->settings['auto_update_users']['default']);

            if ($auto_update_users) {
                $changes = array (
                    'full_name' => $name,
                    'email' => $mail,
                );

                User::model()->updateByPk($oUser->uid, $changes);
                $oUser = $this->api->getUserByName($sUser);
            }

            $this->setAuthSuccess($oUser);
            $this->log(__METHOD__.' - User updated: '.$oUser->uid, \CLogger::LEVEL_TRACE);
        }
        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }
        }
    }

    /**
     * Initialize SAML authentication
     * @return void
     */
    public function get_saml_instance() {

        if ($this->ssp == null) {

            $simplesamlphp_path = $this->get('simplesamlphp_path', null, null, $this->settings['simplesamlphp_path']['default']);

            // To avoid __autoload conflicts, remove limesurvey autoloads temporarily
            $autoload_functions = spl_autoload_functions();
            foreach ($autoload_functions as $function) {
                spl_autoload_unregister($function);
            }

            require_once($simplesamlphp_path.'/lib/_autoload.php');

            $saml_authsource = $this->get('saml_authsource', null, null, $this->settings['saml_authsource']['default']);

            if (class_exists('\SimpleSAML\Auth\Simple')) {
                $this->ssp = new \SimpleSAML\Auth\Simple($saml_authsource);
            }

            // To avoid __autoload conflicts, restote the limesurvey autoloads
            foreach ($autoload_functions as $function) {
                spl_autoload_register($function);
            }
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
        return $this->getSAMLAttribute($this->get('saml_uid_mapping', null, null, $this->settings['saml_uid_mapping']['default']));
    }

    public function getSAMLAttribute(string $attribute_name)
    {
        $attributeValue = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();

        if (!empty($attributes)) {
            if (array_key_exists($attribute_name, $attributes) && !empty($attributes[$attribute_name]))	{
                $attributeValue = $attributes[$attribute_name][0];
            }
        }
        return $attributeValue;
    }

    public function getUserCommonName()
    {
        return $this->getSAMLAttribute($this->get('saml_name_mapping', null, null, $this->settings['saml_name_mapping']['default']));
    }

    public function getUserMail()
    {
        return $this->getSAMLAttribute($this->get('saml_mail_mapping', null, null, $this->settings['saml_mail_mapping']['default']));
    }

    private function getUserGroup()
    {
        return $this->getSAMLAttribute($this->get('saml_group_mapping', null, null, $this->settings['saml_group_mapping']['default']));
    }
}
