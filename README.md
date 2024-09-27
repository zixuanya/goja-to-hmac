# GoJajs实现hmac方法 POV

此代码适用于在goja环境的JavaScript中不依赖golang实现hmac参数的方法

为代码提供了 `hmacSha1(key, message)` `bytesToHex(bytes)` `stringToBytes(str)` `sha1(bytes)` 等参数的兼容

适用于 miaospeed 编写需要hmac的步骤实现等任何需要使用gojajs来实现的内容
