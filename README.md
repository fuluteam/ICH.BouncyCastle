## 简介

加解密现状，编写此系列文章源码的背景：
- 需要考虑系统环境兼容性问题（Linux、Windows）
- 语言互通问题（如C#、Java等）（加解密本质上没有语言之分，所以原则上不存在互通性问题）
- 网上资料版本不一、或不全面
- .NET官方库密码算法提供不全面，很难针对其他语言（Java）进行适配

本系列文章主要介绍如何在 .NET Core 中使用非对称加密算法、编码算法、消息摘要算法、签名算法、对称加密算法、国密算法等一系列算法，如有错误之处，还请大家批评指正。

本系列文章旨在引导大家能快速、轻松的了解接入加解密，乃至自主组合搭配使用BouncyCastle密码术包中提供的算法。


本系列代码项目地址：[https://github.com/fuluteam/ICH.BouncyCastle.git](https://github.com/fuluteam/ICH.BouncyCastle.git)

文章《.NET Core加解密实战系列之——消息摘要与数字签名算法》：[https://www.cnblogs.com/fulu/p/13209066.html](https://www.cnblogs.com/fulu/p/13209066.html)

文章《.NET Core加解密实战系列之——对称加密算法》：
[https://www.cnblogs.com/fulu/p/13650079.html](https://www.cnblogs.com/fulu/p/13650079.html)

文章《.NET Core加解密实战系列之——RSA非对称加密算法》：
[https://www.cnblogs.com/fulu/p/13100471.html](https://www.cnblogs.com/fulu/p/13100471.html)

文章《.NET Core加解密实战系列之——使用BouncyCastle制作p12(.pfx)数字证书》：
[https://www.cnblogs.com/fulu/p/13716553.html](https://www.cnblogs.com/fulu/p/13716553.html)

### 功能依赖

BouncyCastle（https://www.bouncycastle.org/csharp） 是一个开放源码的轻量级密码术包；它支持大量的密码术算法，它提供了很多 .NET Core标准库没有的算法。

支持 .NET 4，.NET Standard 1.0-2.0，WP，Silverlight，MonoAndroid，Xamarin.iOS，.NET Core


| 功能 | 依赖 |
| :-- | :-- |
| Portable.BouncyCastle | [Portable.BouncyCastle &bull; 1.8.5](https://www.nuget.org/packages/Portable.BouncyCastle/1.8.5) |
