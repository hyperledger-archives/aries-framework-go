# Aries Agent Mobile

Mobile bindings for the [Aries Framework Go](github.com/hyperledger/aries-framework-go) library.
> Note: these bindings are experimental and are subject to frequent changes.

## 1. Requirements

- [Golang](https://golang.org/doc/install) >= 1.13
- [Android SDK](https://developer.android.com/studio/install) (via Android Studio)
- [Android NDK](https://developer.android.com/ndk/downloads)
- [XCode](https://developer.apple.com/xcode/) (macOS only)
- Make
    - [Windows](http://gnuwin32.sourceforge.net/packages/make.htm)
    - [macOS](https://brew.sh/) (via Homebrew)
    - Linux (pre-installed)


## 2. Build

Export (or set) the following variables
- `ANDROID_HOME` - the location of the installed Android SDK
- `ANDROID_NDK_HOME` - the location of the installed Android NDK

### 2.1 Make All

```bash
$ make all
```

### 2.2 Make Bindings

#### a. All bindings
```bash
$ make bindings
```

#### b. Android bindings
```bash
$ make bindings-android
```

#### c. iOS bindings
> Please note that this can only be run on macOS.
```bash
$ make bindings-ios
```

## 3. Usage

### a. Android

#### Importing the generated binding as a module in Android Studio
- In the menu of your Android Studio project, go to **File>Project Structure**.
- A modal will be displayed and on the left click on **Modules**.
- In the section title _Modules_ click on the **+**.
- Another modal will be displayed, scroll down and select _Import .JAR/.AAR Package_ and press **Next**.
- In the _File name_ field, enter the path to the `aries-agent.aar` file and click **Finish**.
- Select **Apply** if applicable and then **OK**.
- Reopen the _Project Structure_ modal and on the left click on **Dependencies**.
- Click on **app**. In the section titled _Declared Dependencies_, click on the **+**.
- Click on **Module Dependency** and select `aries-agent.aar`.
- Click **OK** and select **Apply** if applicable and then **OK**.

#### Code sample
This is an example of how the imported module can be used:
```java
import org.hyperledger.aries.api.AriesController;
import org.hyperledger.aries.api.IntroduceController;
import org.hyperledger.aries.ariesagent.Ariesagent;
import org.hyperledger.aries.wrappers.*;
/*
...
*/
        IntroduceActionsResponse res = new IntroduceActionsResponse();
        try {
            boolean useLocalAgent = false;
            AriesController a = Ariesagent.newAriesAgent(useLocalAgent);
            IntroduceController i = a.getIntroduceController();
            res = i.actions(new IntroduceActionsRequest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String actionsResponse = res.getActionsResponse();
```


### b. iOS

#### Importing the generated binding as a framework in XCode
- In the menu of your XCode project, go to **File>Add Files to "your project name"...**.
- In the displayed modal, navigate to the path of your `AriesAgent.framework` file and click **Add**.

#### Code sample
This is an example of how the imported framework can be used:
```objc
#import <AriesAgent/Ariesagent.h>
/*
...
*/
    ApiAriesController *ac = (ApiAriesController*) AriesagentNewAriesAgent(false, nil);
    ApiIntroduceController *ic = (ApiIntroduceController*) [ac getIntroduceController:nil];
    WrappersIntroduceActionsResponse *resp = [ic actions:nil];
    NSString *actionsResp = resp.actionsResponse;
```


### c. Demo apps

For examples of mobile apps built with the aries-agent-mobile bindings, see [trustbloc/aries-examples](https://github.com/trustbloc/aries-examples).


## 4. Test

```bash
$ make unit-test
```


## 5. Release

TODO


## 6. Contribute

See the [guidelines](https://github.com/hyperledger/aries-framework-go/blob/master/.github/CONTRIBUTING.md) from the parent project.
