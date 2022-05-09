# Aries Agent Mobile

Mobile bindings for the [Aries Framework Go](https://github.com/hyperledger/aries-framework-go) library.
> Note: these bindings are experimental and are subject to frequent changes.

## 1. Requirements

- [Golang](https://golang.org/doc/install) >= 1.16
- [Android SDK](https://developer.android.com/studio/install) (via Android Studio)
- [Android NDK](https://developer.android.com/ndk/downloads)
- [Xcode](https://developer.apple.com/xcode/) (macOS only)
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

### 3.1. Android

#### a. Importing the generated binding as a module in Android Studio
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

#### b. Code sample
This is an example of how the imported module can be used:

<details><summary>Java</summary>
<p>

```java
import org.hyperledger.aries.api.AriesController;
import org.hyperledger.aries.api.IntroduceController;
import org.hyperledger.aries.ariesagent.Ariesagent;
import org.hyperledger.aries.models.RequestEnvelope;
import org.hyperledger.aries.models.ResponseEnvelope;
import org.hyperledger.aries.config.Options;

import java.nio.charset.StandardCharsets;
/*
...
*/
        // create options
        Options opts = new Options();
        opts.setAgentURL("http://example.com");
        opts.setUseLocalAgent(false);

        ResponseEnvelope res = new ResponseEnvelope();
        try {
            // create an aries agent instance
            AriesController a = Ariesagent.new_(opts);

            // create a controller
            IntroduceController i = a.getIntroduceController();

            // perform an operation
            byte[] data = "{}".getBytes(StandardCharsets.UTF_8);
            res = i.actions(new RequestEnvelope(data));
        } catch (Exception e) {
            e.printStackTrace();
        }

        String actionsResponse = new String(res.getPayload(), StandardCharsets.UTF_8);
        System.out.println(actionsResponse);
```

</p>
</details>


<details><summary>Kotlin</summary>
<p>
    
```kotlin
import org.hyperledger.aries.ariesagent.Ariesagent
import org.hyperledger.aries.config.Options
import org.hyperledger.aries.models.RequestEnvelope
import org.hyperledger.aries.models.ResponseEnvelope
import java.nio.charset.StandardCharsets
/*
...
*/
        // create options
        val opts = Options()
        opts.agentURL = "http://example.com"
        opts.useLocalAgent = false
        var res = ResponseEnvelope()
        try {
            // create an aries agent instance
            val a = Ariesagent.new_(opts)

            // create a controller
            val i = a.introduceController

            // perform an operation
            val data = "{}".toByteArray(StandardCharsets.UTF_8)
            res = i.actions(RequestEnvelope(data))
        } catch (e: Exception) {
            e.printStackTrace()
        }
        val actionsResponse = String(res.payload, StandardCharsets.UTF_8)
        println(actionsResponse)
```

</p>
</details>

To subscribe to events on an Aries agent, implement the [`Handler`](./pkg/api/handler.go) interface and use as follows:

<details><summary>Java</summary>
<p>
    
```java

import java.nio.charset.StandardCharsets;

import org.hyperledger.aries.api.Handler;

class MyHandler implements Handler {

    @Override
    public void handle(String topic, byte[] message) {
        System.out.println("received notification topic: ", topic);
        System.out.println("received notification message: ", new String(message, StandardCharsets.UTF_8));
    }
}

class AriesService {
    AriesController ariesAgent;

    public void newAgentWithHandler(String url, String websocketURL, bool useLocalAgent) {
        Options opts = new Options();
        opts.setAgentURL(url);
        opts.setWebsocketURL(websocketURL);
        opts.setUseLocalAgent(useLocalAgent);

        try {
            ariesAgent = Ariesagent.new_(opts);

            // register handler
            Handler handler = new MyHandler();
            String registrationID = ariesAgent.registerHandler(handler, "didexchange_states");
            System.out.println("handler registration id: ", registrationID);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

</p>
</details>


<details><summary>Kotlin</summary>
<p>
    
```kotlin

import org.hyperledger.aries.api.AriesController
import org.hyperledger.aries.api.Handler
import org.hyperledger.aries.ariesagent.Ariesagent
import org.hyperledger.aries.config.Options
import java.nio.charset.StandardCharsets

class MyHandler : Handler {
    override fun handle(topic: String, message: ByteArray) {
        println("received notification topic: $topic")
        println("received notification message: " + String(message, StandardCharsets.UTF_8))
    }
}

class AriesService {
    var ariesAgent: AriesController? = null
    fun newAgentWithHandler(url: String?, websocketURL: String?, useLocalAgent: Boolean) {
        val opts = Options()
        opts.agentURL = url
        opts.websocketURL = websocketURL
        opts.useLocalAgent = useLocalAgent
        try {
            ariesAgent = Ariesagent.new_(opts)

            // register handler
            val handler: Handler = MyHandler()
            val registrationID = ariesAgent.registerHandler(handler, "didexchange_states")
            println("handler registration id: $registrationID")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
```

</p>
</details>

### 3.2. iOS

#### a. Importing the generated binding as a framework in Xcode
- In the menu of your Xcode project, go to **File>Add Files to "your project name"...**.
- In the displayed modal, navigate to the path of your `AriesAgent.framework` file and click **Add**.

#### b. Code sample
This is an example of how the imported framework can be used:


<details><summary>Objective-C</summary>
<p>
    
```objc
#import <AriesAgent/Ariesagent.h>
/*
...
*/
    NSError *error = nil;

    // create options
    ConfigOptions *opts = ConfigNew();
    // [opts setAgentURL:@"http://example.com"];
    [opts setUseLocalAgent:true];
    
    // create an aries agent instance
    ApiAriesController *ac = (ApiAriesController*) AriesagentNew(opts, &error);
    if(error) {
        NSLog(@"error creating an aries agent: %@", error);
    }
    
    // create a controller
    ApiVerifiableController *ic = (ApiVerifiableController*) [ac getVerifiableController:&error];
    if(error) {
        NSLog(@"error creating an verifiable controller instance: %@", error);
    }

    // perform an operation
    NSData *data = [@"" dataUsingEncoding:NSUTF8StringEncoding];
    ModelsRequestEnvelope *req = ModelsNewRequestEnvelope(data);
    ModelsResponseEnvelope *resp = [ic getCredentials:req];
    if(resp.error) {
        NSLog(@"error getting credentials: %@", resp.error.message);
    } else {
        NSString *credResp = [[NSString alloc] initWithData:resp.payload encoding:NSUTF8StringEncoding];
        NSLog(@"credentials response: %@", credResp);
    }
```

</p>
</details>


<details><summary>Swift</summary>
<p>
    
```swift
import AriesAgent

/*
...
*/
var error: Error? = nil

// create options
let opts = ConfigNew()
// [opts setAgentURL:@"http://example.com"];
opts?.useLocalAgent = true

// create an aries agent instance
let ac = AriesagentNew(opts, &error) as? ApiAriesController
if let error = error {
    print("error creating an aries agent: \(error)")
}

// create a controller
let ic = ac?.getVerifiableController(&error) as? ApiVerifiableController
if let error = error {
    print("error creating an verifiable controller instance: \(error)")
}

// perform an operation
let data = "".data(using: .utf8)
let req = ModelsNewRequestEnvelope(data)
let resp = ic.getCredentials(req)
if resp?.error != nil {
    if let message = resp?.error.message {
        print("error getting credentials: \(message)")
    }
} else {
    var credResp: String? = nil
    if let payload = resp?.payload {
        credResp = String(data: payload, encoding: .utf8)
    }
    print("credentials response: \(credResp ?? "")")
}
```

</p>
</details>


To subscribe to events on an Aries agent, implement the [`Handler`](./pkg/api/handler.go) interface and use as follows:


<details><summary>Objective-C</summary>
<p>
    
```objc

#import <AriesAgent/Ariesagent.h>

@interface MyHandler: NSObject<ApiHandler>{

}
@end

@implementation MyHandler
    
NSString *lastTopic, *lastMessage;

- (BOOL) handle: (NSString *)topic message:(NSData *)message
          error:(NSError * _Nullable __autoreleasing *)error {
    
    lastTopic = topic;
    lastMessage = [[NSString alloc] initWithData:message encoding:NSUTF8StringEncoding];
        
    return true;
}

@end

@interface AriesService()

@property NSString *urlToUse;
@property NSString *wsURLToUse;
@property BOOL useLocalAgent;
@property ApiAriesController* ariesAgent;

@end

@implementation AriesService

- (void) newAgentWithHandler {
    ConfigOptions *opts = ConfigNew();
    [opts setAgentURL:_urlToUse];
    [opts setUseLocalAgent:_useLocalAgent];
    [opts setWebsocketURL:_wsURLToUse];
    
    NSError *error = nil;
    
    _ariesAgent = (ApiAriesController*) AriesagentNew(opts, &error);
    if(error) {
        NSLog(@"error creating an aries agent: %@", error);
    }
    
    // register handler
    MyHandler *handler = [[MyHandler alloc] init];
    NSString *regID = [_ariesAgent registerHandler:handler topics:@"didexchange_states"];
    NSLog(@"handler registration id: %@", regID);
}

@end

```

</p>
</details>


<details><summary>Swift</summary>
<p>
    
```swift

import AriesAgent

var lastTopic: String?
    var lastMessage: String?

class MyHandler: NSObject, ApiHandler {
    func handle(
        _ topic: String?,
        message: Data?
    ) throws {

        lastTopic = topic
        if let message = message {
            lastMessage = String(data: message, encoding: .utf8)
        }

        return true
    }
}

class AriesService {
    private var urlToUse: String?
    private var wsURLToUse: String?
    private var useLocalAgent = false
    private var ariesAgent: ApiAriesController?

    func newAgentWithHandler() {
        let opts = ConfigNew()
        opts?.agentURL = urlToUse
        opts?.useLocalAgent = useLocalAgent
        opts?.websocketURL = wsURLToUse

        var error: Error? = nil

        ariesAgent = AriesagentNew(opts, &error) as? ApiAriesController
        if let error = error {
            print("error creating an aries agent: \(error)")
        }

        // register handler
        let handler = MyHandler()
        let regID = ariesAgent?.register(handler, topics: "didexchange_states")
        print("handler registration id: \(regID ?? "")")
    }
}

```

</p>
</details>


## 4. Test

```bash
$ make unit-test
```


## 5. Release

TODO


## 6. Contribute

See the [guidelines](https://github.com/hyperledger/aries-framework-go/blob/master/.github/CONTRIBUTING.md) from the parent project.
