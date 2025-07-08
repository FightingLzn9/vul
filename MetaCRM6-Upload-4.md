
### <font style="color:rgb(28, 31, 35);">The `sendfile.jsp` interface has an arbitrary file upload vulnerability.</font>

The number of IPs using this software and their fingerprints are as follows:

1,342 matching results, with 735 unique IPs.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782333856-f16a2cbf-071d-4f15-9b3a-39d858a04271.png?x-oss-process=image%2Fformat%2Cwebp)
<font style="color:rgb(28, 31, 35);">Global search for the keyword "upload" leads to a file upload endpoint. The application uses a custom class `com.metasoft.framework.pub.upload.Upload` to handle file uploads.</font>![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751877443075-9948ae22-8fa6-4bd1-b240-2ce479b226c6.png)

<font style="color:rgb(28, 31, 35);">For the file path parameter `path`, trace the method `com.metasoft.framework.pub.util.Path.getUserFile()`.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751877862391-e62f64ee-00b6-4def-a11a-03fbf0663abb.png)

Here's the English translation of the analysis:

1. `java.io.File.separator`** is used as the system path separator.**
2. **The UUID class is used to rename files**, which prevents directory traversal attacks.
3. **File concatenation vulnerability**: The code directly concatenates `path + fieldID` without validating the file extension. For example:

```java
fileFullName = path + fieldID; // No extension validation
myUpload.saveAs(path, fieldID); // Saves file without checking suffix
```

4. **Resulting file path**: The final file is saved to a temporary directory with a UUID-based name but insecure extension:  
`/userfile/default/temp/random_uuid.ext`

**Security Risk**: Attackers could upload files with dangerous extensions (e.g., `.jsp`, `.jspx`, `.class`) to execute arbitrary code if the server processes these files.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751951439104-f4e474a4-78a1-425b-b0f5-d17d18fc8ce2.png)

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751951460757-6ae4404d-0f6b-47c3-817d-18611d4994d0.png)

