package com.security.cipher.sm;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class SM4Utils
{
	private static String secretKey = "";
	
	private static String iv = "e";
	
	private static boolean hexString = false;
	
	public SM4Utils()
	{
	}
	
	public String encryptData_ECB(String plainText)
	{
		try 
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;
			
			byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes();
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
			String cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public String decryptData_ECB(String cipherText)
	{
		try 
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;
			
			byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes();
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
			return new String(decrypted, "UTF-8");
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public String encryptData_CBC(String plainText)
	{
		try 
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;
			
			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
			String cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public static String decryptData_CBC(String cipherText)
	{
		try 
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;
			
			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}
			
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
			return new String(decrypted, "UTF-8");
		} 
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) throws IOException {

		//解密以下字符
		/*String plainText = "{\"QUERY_RANGE\":\"2\",\"PROVINCE_CODE\":\"11102\"}";//输入密文
		SM4Utils sm4 = new SM4Utils();
		sm4.secretKey = "联系QQ1198287349";
		System.out.println("CBC模式");
		sm4.iv = "联系QQ1198287349";
		String cipherText = sm4.encryptData_CBC(plainText);
		System.out.println("密文: " + cipherText);//明文加密后
		System.out.println("");
		plainText = sm4.decryptData_CBC(cipherText);
		System.out.println("明文: " + plainText);//拿到明文*/

		//解密一下字符
		SM4Utils sm4 = new SM4Utils();
		sm4.secretKey = "联系QQ1198287349";
		sm4.iv = "联系QQ1198287349";
		String ctext = "415Sez/Jai9DUg8F9uohyg==\"";//输入密文
		String plainText = sm4.decryptData_CBC(ctext);
		System.out.println("明文: " + plainText);//拿到明文
		System.out.println("");
		String cipherText = sm4.encryptData_CBC(plainText);
		System.out.println("密文: " + cipherText);//明文加密后




	}
}
