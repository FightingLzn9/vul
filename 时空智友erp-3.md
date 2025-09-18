## Shikong Zhiyou ERP is vulnerable to XML External Entity (XXE) injection vulnerability

Official Website：http://bjskzy.com/

System fingerprint status The system fingerprint status is as follows:

There are more than a thousand users using it across the entire network. 
<img width="2550" height="1362" alt="image" src="https://github.com/user-attachments/assets/9dc86451-aa9a-4b5a-bf2b-2f6161844d93" />

### Vulnerability Analysis

com.artery.richclient.RichClientService#openForm has an XXE vulnerability

The OpenForm parameter here can receive an XML from the outside, and there is no authentication, which creates an exploitable opportunity.

<img width="1365" height="805" alt="image" src="https://github.com/user-attachments/assets/d7e7acc2-2634-4df7-a1a4-63bebdbc178a" />


Directly passing in a malicious XML will cause parsing in the Formservice class.
<img width="1651" height="687" alt="image" src="https://github.com/user-attachments/assets/84d87d8e-f4ea-4afa-a152-6e92d71b9701" />

Thus, a PoC can be constructed as follows:

<img width="2036" height="991" alt="image" src="https://github.com/user-attachments/assets/7ef7381c-4931-4fa2-bba7-044977f58496" />


Thank you for your review, and wish you happiness every day.
