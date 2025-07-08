### The mcc_login.jsp interface in MetaCRM6 is vulnerable to SQL injection
<font style="color:rgba(0, 0, 0, 0.85);">A SQL injection sink point has been identified through global search, specifically at a parameter concatenation location.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751781143818-fbaefd78-40a9-4ccf-a109-f3d18644139e.png)

<font style="color:rgba(0, 0, 0, 0.85);">Upon examining the "getArray "method in the "com.metasoft.framework.db.DBManager" class, it was found that parameters are directly concatenated into the SQL statement without any filtering or sanitization before execution.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751781308738-d0c5e065-18b6-4e0d-bbb9-98c90b79613d.png)

<font style="color:rgba(0, 0, 0, 0.85);">This oversight leads to a SQL injection vulnerability exploitable via the front end.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751781475170-50b18937-1e0d-4e67-850a-48a57598f266.png)

#### 
