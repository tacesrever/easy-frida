
# typescript plugin  
AutoComplete plugin for frida's java warpper.  

![](./example.png)

# Useage  
add plugin config in tsconfig.json:  

    {
        "compilerOptions": {
            ...
            },
            "plugins": [{
                "name": path_to_tsplugin,
                "classPaths": [
                    path_to_android_sdk_jar(usually at SDKROOT/platforms/android-sdklevel/android.jar),
                    path_to_apk_dex2jar_jar,
                    ...
                ],
                "logfile"?: path_to_logfile
            }]
        }
    }