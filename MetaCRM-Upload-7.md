### <font style="color:rgb(28, 31, 35);">The `/business/common/sms/sendsms.jsp` interface is vulnerable to arbitrary file upload attacks. The relevant upload code is as follows:</font>

<font style="color:rgb(28, 31, 35);">The number of IPs using this software and their fingerprints are as follows:</font>

**<font style="color:rgb(28, 31, 35);">1,342 matching results, with 735 unique IPs.</font>**

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751782333856-f16a2cbf-071d-4f15-9b3a-39d858a04271.png?x-oss-process=image%2Fformat%2Cwebp)

```java
<%

	com.metasoft.framework.pub.upload.Upload myUpload=new com.metasoft.framework.pub.upload.Upload();	
	myUpload.initialize(pageContext);
	myUpload.upload();

	
	String touser = myUpload.getRequest().getParameter("touser");
	String subject = myUpload.getRequest().getParameter("subject");
	
	
	String affix = myUpload.getFiles().getFile(0).getFileName();
	String body = myUpload.getRequest().getParameter("body");

	int iCount = myUpload.getFiles().getFile(0).getSize();
	
	//System.out.println("iCount="+iCount);
	
	String path = com.metasoft.framework.pub.util.Path.getUserFile()+"temp"+java.io.File.separator;
	String fileFullName = "";

	if (iCount != 0) {
		String fieldID = com.metasoft.framework.pub.util.UUID.getID();
		if(affix.indexOf(".")!=-1)
			fieldID +=affix.substring(affix.lastIndexOf("."));
			
		myUpload.saveAs(path, fieldID);
		fileFullName = path+fieldID;

	}
```

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751968037509-073ebd07-02b1-4f74-a57d-a08fb9c96ac4.png)

<font style="color:rgb(28, 31, 35);">The system does not validate the file extension, directly saving files which creates an arbitrary file upload vulnerability. However, it should be noted that this interface requires a valid cookie to be present.</font>

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751970081707-ebfd5165-746d-463e-a048-50b94240b139.png)

![](https://cdn.nlark.com/yuque/0/2025/png/50620181/1751970153216-21863621-95d9-41b6-81bd-76c9b945b470.png)



This proves that the vulnerability exists.

Wish you a pleasant life, and thank you for your review!

