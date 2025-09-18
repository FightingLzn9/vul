## The sqlresult interface of Shikong Zhiyou ERP has a SQL injection vulnerability.
System fingerprint status The system fingerprint status is as follows: 
There are more than a thousand users using it across the entire network.
<img width="2550" height="1362" alt="image" src="https://github.com/user-attachments/assets/32a2a886-a50c-4a6f-8142-029dbb2685a5" />

## Vulnerability Analysis
There is a sink point in com.artery.workflow.ServiceImpl. It can be seen that a parameter named "sql" is directly received from the outside here and then passed into the getFieldValue method.
<img width="1225" height="525" alt="image" src="https://github.com/user-attachments/assets/1fe1da5b-bc30-4e58-b2fc-dc9fb1cbf8ff" />

Following up again, the externally passed SQL parameter is directly executed here, leading to SQL injection.
<img width="1411" height="704" alt="image" src="https://github.com/user-attachments/assets/6ae7cb8a-a619-4cfc-a7bd-3661799b71f9" />
Note that in this constructor, params, as a JSONObject, needs to have an additional key-value pair embedded within it.

<img width="1842" height="544" alt="image" src="https://github.com/user-attachments/assets/5b16673e-929c-4afb-8ce3-8fe544fa447f" />

