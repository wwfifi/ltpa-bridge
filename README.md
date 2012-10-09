# LTPA Token Generation HTTP resource bridge
	
What
----
Java web application making bridging from Jasig CAS authentication to LTPA token generation.  Generates an LTPA token asserting the username provided by CAS.  

Suitable for adaptation to any other reasonable login mechanism or single sign-on regime, of course, since the LTPA token generation bit simply asserts the username available from httpServletRequest.getRemoteUser().  (Here as populated by the CAS client in use.)


Configure
--------
* Configure values in the property file `src/main/resources/ltpa.properties` appropriate to your environment.
* In `src/main/resources/shiro.ini` file change: `casRealm.casServerUrlPrefix`, `casRealm.casService`, `user.loginUrl` properties appropriate to your environment.

Build
-----
From the root of the project directory run `gradlew`. The resulting artifacts will be created in the `build` directory: `build/libs/ltpa.war` archive and `build/ltpa` exploded war directory (if you prefer deploy it that way).