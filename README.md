# Transit card notes

> [!NOTE]
> Please do not send MRs. Issues are alright.

## Initial observations

1. Very similar to Suica. But, why no HCE emulation via IOS/Android ?
2. PPSE is present. So there should be multiple AIDs present in card. (similar to KochiOne cards).

## General Reading (off of blinkit | same as Airtel's)

#### Meta about protocol

1. 7 byte UID - `02:7F:XX:XX:XX:XX:XX`
2. ATQA is `0x4400`. It identifies as a `Type A` card. (ISO 14443-3 & 4)
3. SAK is `0x20`. ISO-DEP compatible, Type 4 (ISO 14443-4). Similar to DMRC's DESFire cards, Android HCE should be possible.
   1. It can also mean that it can handle offline data authentication. Similar to DMRC's transit card.
4. ATS: `0x1478007102<3101F1564011002B00000000000000>`
   1. FSCI: 8
   2. SFGT: 1
   3. FWI: 7 (~38.6 ms) (can be relayed 😄)
   
#### FCI

1. PPSE DIR: `6F 32 84 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 A5 20 BF 0C 1D 61 1B 4F 07 A0 00 00 05 24 10 10 50 0D 52 75 50 61 79 20 50 72 65 50 61 69 64 87 01 01` | `o2..2PAY.SYS.DDF01. ...a.O.....$..P.RuPay PrePaid...` |
   1. Card responded to `2PAY.SYS.DDF01` PPSE selection
   2. Block `A0 00 00 05 24 10 10` is Rupay AID.
   3. Block `87 01 01` sets this AID as the default payment application on this card. (Priority set to 1)
2. Default selected AID: `6F 10 A5 04 9F 65 01 FF 84 08 A0 00 00 01 51 00 00 00` | `o....e........Q...` |
   1. Default AID is not Rupay. It's `Global Platform card manager`. Version `2.2.1`. ([GPC Card Spec, Page 325, Sec H.1.3](https://globalplatform.org/wp-content/uploads/2018/05/GPC_CardSpecification_v2.3.1_PublicRelease_CC.pdf))

#### Other info

Upon further scanning, the card itself also emulates MiFare Plus card (SL3).

## Problems

1. GP Secure Channel Protocol (SCP) is set to 02 which is deprecated by Global Platform because of deterministic encryption. 3DES in CBC with fixed IV of zeroes. Plaintext recovery attack is possible.

## The app

Made with flutter. Relies on [flutter-nfc-manager](https://github.com/okadan/flutter-nfc-manager) for NFC related stuff. The system bindings are done via pigeon and the header file for that is located [here](https://github.com/okadan/flutter-nfc-manager/blob/main/pigeon/android.dart). 

One of the things can be to now set hooks or patch all the functions defined in the header to log out the APDU commands and their responses. This could also mean that a patch for the app should be enough to increase, let's say, the money field right before a top-up APDU is being sent. Though it'll be encrypted, I think.

The app has some restrictions on rooted phone and developer mode. The method that takes care of it is located on the kotlin side. Here's a frida snippet to fix it -- 

```js
var MainActivity = Java.use("com.pinelabs.bharatyatra.MainActivity");
MainActivity["checkDeviceSecurity"].implementation = function () {
   // True == don't run the app
   // False == everything good.
   return false;
};
```

To target patching, there's a hash check function. Here's a bypass for it -- 

```js
var MainActivity = Java.use("com.pinelabs.bharatyatra.MainActivity");
MainActivity["verifyAppSignature"].implementation = function () {
   return true;
};
```

There's a google play api check as well. Bypass --

```js
var GoogleApiAvailability = Java.use("com.google.android.gms.common.GoogleApiAvailability");
GoogleApiAvailability["isGooglePlayServicesAvailable"].overload('android.content.Context').implementation = function (context) {
   return 0;
};
```

Note that the activity `com.pinelabs.bharatyatra.MainActivity` also handles offline balance queries / top-up from the card.


## Offline data & The transit card side of NCMC

I'll fill this once I actually get a card in hand. I'll try to relay info because HCE should be possible with the current card arch.
