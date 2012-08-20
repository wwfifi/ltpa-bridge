# LTPA Token Generation HTTP resource bridge
	
Configure
--------
* Configure values in the property file `src/main/resources/ltpa.properties` appropriate to your environment.
* In `src/main/resources/shiro.ini` file change: `casRealm.casServerUrlPrefix`, `casRealm.casService`, `user.loginUrl` properties appropriate to your environment.

Build
-----
From the root of the project directory run `gradlew`. The resulting artifacts will be created in the `build` directory: `build/libs/ltpa.war` archive and `build/ltpa` exploded war directory (if you prefer deploy it that way).