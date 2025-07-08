### <font style="color:rgba(0, 0, 0, 0.85);">The </font>`<font style="color:rgba(0, 0, 0, 0.85);">/common/jsp/upload2.jsp</font>`<font style="color:rgba(0, 0, 0, 0.85);"> interface is vulnerable to arbitrary file upload attacks.</font>
<font style="color:rgba(0, 0, 0, 0.85);">Let's analyze this code carefully as it has some unique features:</font>  
![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751882304870-74c42ffd-ca2f-48ab-b14c-92cca2f3ca62.png)

<font style="color:rgba(0, 0, 0, 0.85);">Authentication code exists in this interface, indicating it is a backend function.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889180885-91bfdb25-97d3-41df-b1be-d712791c70e3.png)

<font style="color:rgb(28, 31, 35);">And these parameters are passed in.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889290572-0cfd82e4-825b-457d-87ef-e2d708ce317b.png)

<font style="color:rgb(28, 31, 35);">If `strType` equals "delete", the content pointed to by the `titlevalue` parameter will be deleted.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889493653-91751a40-8831-4418-bf1d-453eb30a44bf.png)

If `strType` does **not** equal "delete", the code performs a file upload operation. The file path is directly concatenated **without validating the file extension**, leading to an arbitrary file upload vulnerability.

**POC Construction Steps:**

1. **Obtain Valid Session Cookies**: Since this is a backend vulnerability, you need to authenticate first (e.g., via login or session hijacking).
2. **Craft Malicious Payload**: Upload a file with a dangerous extension (e.g., `.jsp`, `.jspx`, `.php`) containing reverse shell code.
3. **Trigger Execution**: Access the uploaded file via its URL to execute code on the server.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751890839524-2c5ae0d3-cc00-45b7-bdc9-8c31cd57f680.png)

<font style="color:rgba(0, 0, 0, 0.85);">Let's analyze the file upload path next:</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751936332613-0f819312-420c-41f5-b9ec-d8a194a2850b.png)

The storage path is constructed as path + affixID, where affixID is a randomly generated filename. Next, we need to analyze where the path parameter originates.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892155886-be88986c-8e60-4081-86c5-77e546ce93b6.png)

<font style="color:rgba(0, 0, 0, 0.85);">The storage path is constructed as </font>`<font style="color:rgba(0, 0, 0, 0.85);">path + affixID</font>`<font style="color:rgba(0, 0, 0, 0.85);">, where </font>`<font style="color:rgba(0, 0, 0, 0.85);">affixID</font>`<font style="color:rgba(0, 0, 0, 0.85);"> is a randomly generated filename. Next, we need to analyze where the </font>`<font style="color:rgba(0, 0, 0, 0.85);">path</font>`<font style="color:rgba(0, 0, 0, 0.85);"> parameter comes from.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892520392-4af3c461-2d2b-4f90-8eab-459b75e7910e.png)

<font style="color:rgba(0, 0, 0, 0.85);">If </font>`<font style="color:rgba(0, 0, 0, 0.85);">sCorpName</font>`<font style="color:rgba(0, 0, 0, 0.85);"> is empty, assign it the value "default" and proceed to call the </font>`<font style="color:rgba(0, 0, 0, 0.85);">getEnterpriseUserFile()</font>`<font style="color:rgba(0, 0, 0, 0.85);"> function.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892556599-8febf3d0-0071-4861-86f8-d4f054d35869.png)

<font style="color:rgba(0, 0, 0, 0.85);">If </font>`<font style="color:rgba(0, 0, 0, 0.85);">strUserFile</font>`<font style="color:rgba(0, 0, 0, 0.85);"> is empty, assign it the value "userfile". Finally, concatenate it with other components to form </font>`<font style="color:rgba(0, 0, 0, 0.85);">resultPath</font>`<font style="color:rgba(0, 0, 0, 0.85);"> and return.</font>  
**The final path structure is clear**<font style="color:rgba(0, 0, 0, 0.85);">: </font>`<font style="color:rgba(0, 0, 0, 0.85);">/userfile/default/temp/random_filename.extension</font>`<font style="color:rgba(0, 0, 0, 0.85);">.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892028124-972042de-fd94-4922-b35d-a168e936374c.png)



This proves that the vulnerability exists.

Wish you a pleasant life, and thank you for your review!

