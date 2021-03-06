package org.apache.shiro.spring.boot.qrcode.endpoint;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSONObject;
import com.beust.jcommander.internal.Maps;
import com.google.zxing.spring.boot.ZxingQrCodeTemplate;

@RestController("/authz/qrcode/")
public class ShiroQrcodeEndpoint {
	
	private static final String STATUS_BOUND = "bound";
	private static final String STATUS_UNBIND = "unbind";
	private static final String STATUS_EXPIRED = "expired";
	
    private final StringRedisTemplate stringRedisTemplate;
    private final ZxingQrCodeTemplate qrcodeTemplate;
	
	public ShiroQrcodeEndpoint(StringRedisTemplate stringRedisTemplate, ZxingQrCodeTemplate qrcodeTemplate) {
		super();
		this.stringRedisTemplate = stringRedisTemplate;
		this.qrcodeTemplate = qrcodeTemplate;
	}

	/*
	 * 前端点击二维码登录时，访问该接口获取二维码数据并在界面展示
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @return
	 * @throws Exception
	 */
	@GetMapping("info")
	@ResponseBody
	public ResponseEntity<Map<String, Object>> qrcode() {
		
		Map<String, Object> rtMap = Maps.newHashMap();
		
		try {
			
			// 生成UUID
			String uuid = UUID.randomUUID().toString();
			String qrcode = getQrcodeTemplate().qrcodeBase64(uuid);
			// 每个老师的随机码都不相同 ： 打卡方式(1:定位打卡,2:刷脸打卡,3:数字打卡,4:二维码打卡,5:无感打卡)
			getStringRedisTemplate().opsForValue().set(String.format("login-%s", uuid), STATUS_UNBIND, Duration.ofMinutes(1));
			
			rtMap.put("code", 0);
			rtMap.put("uuid", uuid);
			rtMap.put("qrcode", qrcode);
			
			return ResponseEntity.ok(rtMap);
		} catch (Exception e) {
			rtMap.put("code", 500);
			rtMap.put("message", ExceptionUtils.getRootCauseMessage(e));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(rtMap);
		}
	}
	
	@PostMapping("bind")
	@ResponseBody
	public ResponseEntity<Map<String, Object>> bind(@RequestParam String uuid) {
		
		Map<String, Object> rtMap = Maps.newHashMap();
		
		try {
			
			rtMap.put("code", 0);
			
			String key = String.format("login-%s", uuid);
			// 没有uuid对应的key，说明二维码过期，需要重新获取新的二维码
			if(!getStringRedisTemplate().hasKey(key)) {
				
				String new_uuid = UUID.randomUUID().toString();
				String qrcode = getQrcodeTemplate().qrcodeBase64(new_uuid);
				
				// 每个老师的随机码都不相同 ： 打卡方式(1:定位打卡,2:刷脸打卡,3:数字打卡,4:二维码打卡,5:无感打卡)
				getStringRedisTemplate().opsForValue().set(String.format("login-%s", new_uuid), STATUS_UNBIND, Duration.ofMinutes(1));
				
				rtMap.put("uuid", new_uuid);
				rtMap.put("qrcode", qrcode);
				rtMap.put("status", STATUS_EXPIRED);
				
				return ResponseEntity.ok(rtMap);
			}
			
			// 每个老师的随机码都不相同 ： 打卡方式(1:定位打卡,2:刷脸打卡,3:数字打卡,4:二维码打卡,5:无感打卡)
			String value = getStringRedisTemplate().opsForValue().get(key);
			// 默认值表示移动端还未进行扫码
			if(STATUS_UNBIND.equalsIgnoreCase(value)) {
				rtMap.put("status", STATUS_UNBIND);
				return ResponseEntity.ok(rtMap);
			}
			
			// 数据已经和用户信息关联
			rtMap.put("info", JSONObject.parseObject(value));
			rtMap.put("status", STATUS_BOUND);
			return ResponseEntity.ok(rtMap);
			
		} catch (Exception e) {
			rtMap.put("code", 500);
			rtMap.put("message", ExceptionUtils.getRootCauseMessage(e));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(rtMap);
		}
	}
	
	public StringRedisTemplate getStringRedisTemplate() {
		return stringRedisTemplate;
	}

	public ZxingQrCodeTemplate getQrcodeTemplate() {
		return qrcodeTemplate;
	}
	
}
