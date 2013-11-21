simple LDAP auth
================

class for very simple ldap auth cheks if user exists and if he/she is in given group.

Usage:
------

Init sample
```PHP
    // Active Directory server
    $ldap_host = "123.123.123.123";//IP adress or url

    // Active Directory DN
    $ldap_dn = 'DC=domain,DC=com';//domain in this example is used "domain.com"

    // Active Directory user group
    $ldap_user_group = "Group Name";

    // Active Directory manager group
    $ldap_manager_group = "Admins";

    // Domain, for purposes of constructing $user
    $ldap_usr_dom = "@domain.com";

    //class inicialization
    $ldap=new \LDAP\auth($ldap_host, $ldap_dn, $ldap_user_group, $ldap_manager_group, $ldap_usr_dom);
```


For auth use like this(expects inicialized class in $ldap)

first argument is username second is passoword
```PHP
    try {
        $ldap->authenticate($user, $pass);
    } catch (Exception $exc) {
        $msg=$exc->getMessage();
        $code=$exc->getCode();

        //this is how we can determine if user dont have corect group but exist on LDAP
        if($ldap::ERROR_WRONG_USER_GROUP==$code){
            //custom handling
        }
    }
```


Thumbnail img retrival example
```PHP
    try {
        $ldap->userInit($user, $pass);
        //we can display it like this
        echo '<img src="'.$ldap->getLDAPimg().'">';

    } catch (Exception $exc) {
        $msg=$exc->getMessage();
        $code=$exc->getCode();

        //react to problems
    }
```


Exeptions Error codes
```PHP
    $ldap::ERROR_WRONG_USER_GROUP

    $ldap::ERROR_CANT_AUTH

    $ldap::ERROR_CANT_SEARCH

    $ldap::ERROR_IMG_DECODE
```
