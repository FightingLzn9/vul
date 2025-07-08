### The /common/jsp/upload2.jsp interface is vulnerable to arbitrary file upload attacks.
The number of IPs using this software and their fingerprints are as follows:

1,342 matching results, with 735 unique IPs.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782333856-f16a2cbf-071d-4f15-9b3a-39d858a04271.png?x-oss-process=image%2Fformat%2Cwebp)

<font style="color:rgba(0, 0, 0, 0.85);">Let's analyze this code carefully as it has some unique features:</font>  
![](https://github.com/FightingLzn9/vul/blob/main/image%20(1).png)

<font style="color:rgba(0, 0, 0, 0.85);">Authentication code exists in this interface, indicating it is a backend function.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889180885-91bfdb25-97d3-41df-b1be-d712791c70e3.png)

<font style="color:rgb(28, 31, 35);">And these parameters are passed in.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889290572-0cfd82e4-825b-457d-87ef-e2d708ce317b.png)

<font style="color:rgb(28, 31, 35);">If `strType` equals "delete", the content pointed to by the `titlevalue` parameter will be deleted.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751889493653-91751a40-8831-4418-bf1d-453eb30a44bf.png)

If `strType` does **not** equal "delete", the code performs a file upload operation. The file path is directly concatenated **without validating the file extension**, leading to an arbitrary file upload vulnerability.

**POC Construction Steps:**

1. **Obtain Valid Session Cookies**: Since this is a backend vulnerability, you need to authenticate first (e.g., via login or session hijacking).
2. **Craft Malicious Payload**: Upload a file with a dangerous extension (e.g., `.jsp`, `.jspx`, `.php`) containing reverse shell code.
3. **Trigger Execution**: Access the uploaded file via its URL to execute code on the server.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751890839524-2c5ae0d3-cc00-45b7-bdc9-8c31cd57f680.png)

Let's analyze the file upload path next:

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751936332613-0f819312-420c-41f5-b9ec-d8a194a2850b.png)

The storage path is constructed as path + affixID, where affixID is a randomly generated filename. Next, we need to analyze where the path parameter originates.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892155886-be88986c-8e60-4081-86c5-77e546ce93b6.png)

The storage path is constructed as path + affixID is a randomly generated filename. Next, we need to analyze where the path parameter comes from.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892520392-4af3c461-2d2b-4f90-8eab-459b75e7910e.png)

If sCorpName is empty, assign it the value "default" and proceed to call the getEnterpriseUserFile() function.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892556599-8febf3d0-0071-4861-86f8-d4f054d35869.png)

If strUserFile is empty, assign it the value "userfile". Finally, concatenate it with other components to form resultPath and return.
**The final path structure is clear: /userfile/default/temp/random_filename.extension.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751892028124-972042de-fd94-4922-b35d-a168e936374c.png)



This proves that the vulnerability exists.

Wish you a pleasant life, and thank you for your review!

