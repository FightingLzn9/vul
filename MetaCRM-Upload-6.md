### <font style="color:rgba(0, 0, 0, 0.85);">The "mobileupload.jsp" interface is vulnerable to arbitrary file upload attacks from the frontend.</font>
The number of IPs using this software and their fingerprints are as follows:

1,342 matching results, with 735 unique IPs.

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782333856-f16a2cbf-071d-4f15-9b3a-39d858a04271.png?x-oss-process=image%2Fformat%2Cwebp)
<font style="color:rgb(28, 31, 35);">We've reached a file upload sink point:</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751966752024-a73d0e77-0d95-4772-907a-6653b08d20c4.png)

<font style="color:rgba(0, 0, 0, 0.85);">The file extension is not validated at all, and the "item.write()" function is directly used to perform the upload operation.</font>  
**Exploitation Path**<font style="color:rgba(0, 0, 0, 0.85);">: Attackers can leverage this vulnerability to upload arbitrary files (e.g., JSP/PHP shells) via this interface.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751966904646-77629f28-f259-4471-b6da-8e7f0b061f77.png)

<font style="color:rgb(28, 31, 35);">Moreover, the storage path of the file is also provided in the response packet. The verification screenshot is as follows:</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751941710149-fd38a518-7a25-4652-9e07-02b352a13f5a.png?x-oss-process=image%2Fformat%2Cwebp)

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751941763252-5302c981-bbad-4162-bebd-84fafebbaa2f.png?x-oss-process=image%2Fformat%2Cwebp)

This proves that the vulnerability exists.



Wish you a pleasant life, and thank you for your review!

