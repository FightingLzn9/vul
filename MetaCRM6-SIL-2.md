### <font style="color:rgba(0, 0, 0, 0.85);">The two interfaces /env.jsp and /debug.jsp have front-end sensitive information leakage vulnerabilities.</font>
<font style="color:rgb(28, 31, 35);">The `/env.jsp` and `/debug.jsp` endpoints are vulnerable to information disclosure. Unauthenticated attackers can access `/env.jsp` to obtain sensitive information such as the server name, Java version, and absolute file paths. </font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782159433-61f1e490-1fe6-40d4-bce9-1ed9a006c784.png)

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782136377-404d0634-14fa-4694-9fc3-1e86f7ff2a9f.png)

<font style="color:rgb(28, 31, 35);">Additionally, the `/debug.jsp` endpoint lacks authentication controls, allowing unauthorized users to perform privileged operations, including modifying server debugging settings and accessing sensitive server logs. Immediate remediation is recommended to prevent potential system compromise.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782468428-d6e64253-62f6-4dac-80e2-37f4b6b26e07.png)

#### 
