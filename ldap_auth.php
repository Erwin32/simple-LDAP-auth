<?php
/**
 * simple class for LDAP authentification
 * 
 Copyright (C) 2013 Petr Palas

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * inspired by http://samjlevy.com/2010/09/php-login-script-using-ldap-verify-group-membership/
 */

namespace LDAP;

use Exception;

class auth {
    /**
     * url or ip of ldap server
     * @var type string
     */
    protected $ldap_host;
    /**
     * active directory DN
     * @var type string
     */
    protected $ldap_dn;
    /**
     * target user group
     * @var type string
     */
    protected $ldap_user_group;
    /**
     * manager group (shud contain users with management access)
     * @var type string
     */
    protected $ldap_manager_group;
    /**
     * contains email domain like "@somedomain.com"
     * @var type string
     */
    protected $ldap_usr_dom;
    
    /**
     * countains connection resource
     * @var type resource
     */
    protected $ldap;
    
    /**
     * contains status text
     * if exeption is thrown msg contains this string
     * @var type string
     */
    public $status;
    /**
     * contains result array if ldap_search is succesfull
     * @var type array
     */
    public $result;
    /**
     * contains auth state 0=unathrized 1=authorized
     * @var type int
     */
    public $auth=0;
    /**
     * contains access level 0=none or unathorized 1=user 2=managment acc
     * @var type int
     */
    public $access=0;
    
    /**
     * contains username after user init
     * @var type string
     */
    public $user;
    
    /**
     * contain user password after user init
     * @var type string
     */
    protected $password;
    
    const ERROR_WRONG_USER_GROUP=2;
    const ERROR_CANT_AUTH=1;
    const ERROR_CANT_SEARCH=3;
    const ERROR_IMG_DECODE=4;
    const ERROR_CANT_CONNECT=5;

    /**
     * loads passed configuration and inits connection
     * @param type $ldap_host
     * @param type $ldap_dn
     * @param type $ldap_user_group
     * @param type $ldap_manager_group
     * @param type $ldap_usr_dom
     */
    function __construct($ldap_host,$ldap_dn,$ldap_user_group,$ldap_manager_group,$ldap_usr_dom) {
        $this->ldap_host=$ldap_host;
        $this->ldap_dn=$ldap_dn;
        $this->ldap_user_group=$ldap_user_group;
        $this->ldap_manager_group=$ldap_manager_group;
        $this->ldap_usr_dom=  '@'.trim($ldap_usr_dom,'@');
        
        $this->init_connection();
    }
    
    /**
     * well destructor :P
     */
    public function __destruct() {
        //kdyby nahodou nebylo unbidnuto
        @ldap_unbind($this->ldap);
    }
    
    /**
     * dumps result array for debug
     */
    public function dump_resut() {
        echo '<pre>';
        print_r($this->result,FALSE);
        echo '</pre>';
    }
    
    /**
     * Inits connection to LDAP server throws exeption on failure
     * @return boolean
     * @throws Exception
     */
    protected function init_connection(){
        $this->ldap=ldap_connect($this->ldap_host,3268);
        if($this->ldap){
            $this->status='connected :)';
            ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION,3);
            ldap_set_option($this->ldap, LDAP_OPT_REFERRALS,0);
        }
        else {
            $this->status='Cant connect to LDAP';
            throw new Exception($this->status,  self::ERROR_CANT_CONNECT);
        }
        return TRUE;
    }
    
    public function userInit($user,$password) {
        $this->user=$user;
        $this->password=$password;
        
        return TRUE;
    }
    
    /**
     * Converts Binary string (like thumbnail from LDAP to base64 datastring for display
     * @param type $file
     * @param type $mime
     * @return type base64 datastring
     */
    protected function data_uri($file, $mime) {  
      $base64   = base64_encode($file); 
      return ('data:' . $mime . ';base64,' . $base64);
    }
    
    /**
     * Gets LDAP thumbnail img
     * @param type $user
     * @param type $password
     * @return type base64 datatring of the thumbnail
     * @throws Exception
     */
    public function getLDAPimg($user=null,$password=null) {
        $newCredentials=TRUE;
        //since we cant set those in param def
        if($password===null){$password=  $this->password;$newCredentials=FALSE;}
        if($user===null){$user=  $this->user;$newCredentials=FALSE;}
        //store user pass and name for future use
        if($newCredentials){$this->userInit($user, $password);}
        
        
        $bind = ldap_bind($this->ldap, $user . $this->ldap_usr_dom, $password);//ldap_bind($this->ldap, $this->ldap_dn, $password);
        
        if($bind){
            $filter = "(sAMAccountName=" . $user . ")";
            $attr = array("thumbnailphoto");
            $result = @ldap_search($this->ldap, $this->ldap_dn, $filter, $attr);
            if($result==FALSE){
                throw new Exception("Unable to search LDAP server. Reason: ".  ldap_error($this->ldap),  self::ERROR_CANT_SEARCH);
            }  
            $entry= ldap_first_entry($this->ldap, $result);

            if ($entry) {
                $info = ldap_get_values_len($this->ldap, $entry, "thumbnailphoto");
                if(!$info){
                   throw new Exception("Unable to decode thumbnail. Error: ".  ldap_error($this->ldap),  self::ERROR_IMG_DECODE);
                }
                //echo '<img src="'.$this->data_uri($info[0], 'image/png').'">';
            }
            
            ldap_unbind($this->ldap);
            return $this->data_uri($info[0], 'image/png');
        }
        else {
            // invalid name or password
            $this->status='Cant authenticate for search on LDAP';
            throw new Exception($this->status.' '.  ldap_error($this->ldap), self::ERROR_CANT_AUTH);
        }
    }
    
    /**
     * Tries to authenticate suplied user with suplied pass
     * @param type $user
     * @param type $password
     * @return boolean
     * @throws Exception
     */
    public function authenticate($user=null, $password=null) {
        $newCredentials=TRUE;
        //since we cant set those in param def
        if($password===null){$password=  $this->password;$newCredentials=FALSE;}
        if($user===null){$user=  $this->user;$newCredentials=FALSE;}
        //store user pass and name for future use
        if($newCredentials){$this->userInit($user, $password);}
        // verify user and password
        $bind = @ldap_bind($this->ldap, $user . $this->ldap_usr_dom, $password);

        
        if($bind) {
            // valid
            // check presence in groups
            $filter = "(sAMAccountName=" . $user . ")";
            $attr = array("memberof");
            $result = @ldap_search($this->ldap, $this->ldap_dn, $filter, $attr);
            if($result==FALSE){
                 throw new Exception("Unable to search LDAP server. Reason: ".  ldap_error($this->ldap),  self::ERROR_CANT_SEARCH);
            }  
            $entries = ldap_get_entries($this->ldap, $result);
            
            //save result for future use
            $this->result=$entries;

            ldap_unbind($this->ldap);

            // check groups
            foreach($entries[0]['memberof'] as $grps) {
                // is manager, break loop
                if (strpos($grps, $this->ldap_manager_group)) { $access = 2; break; }

                // is user
                if (strpos($grps, $this->ldap_user_group)) $access = 1;
            }

            if ($access != 0) {
                // establish result vars
                
                $this->status='Authenticated';
                $this->access=$access;
                $this->user= $user;
                $this->auth=1;
                return true;
            } else {
                // user has no rights
                $this->access=$access;
                $this->user= $user;
                $this->auth=1;
                $this->status='User exists but not part of the target group';
                throw new Exception($this->status.' '.  ldap_error($this->ldap),  self::ERROR_WRONG_USER_GROUP);
            }

        } else {
            // invalid name or password
            $this->status='Cant authenticate for search on LDAP';
            throw new Exception($this->status.' '.  ldap_error($this->ldap),  self::ERROR_CANT_AUTH);
        }
    }

}

