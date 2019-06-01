package com.example.demo2.util;

import org.apache.tomcat.util.codec.binary.StringUtils;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import sun.misc.BASE64Decoder;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class SM2 {
    public static void main(String[] args) throws Exception {
        // 获取SM2 椭圆曲线推荐参数
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
// 构造EC 算法参数
        ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
                // 设置SM2 算法的 OID
                GMObjectIdentifiers.sm2p256v1.toString()
                // 设置曲线方程
                , ecParameters.getCurve()
                // 椭圆曲线G点
                , ecParameters.getG()
                // 大整数N
                , ecParameters.getN());
// 创建 密钥对生成器
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

// 使用SM2的算法区域初始化密钥生成器
        gen.initialize(sm2Spec, new SecureRandom());
// 获取密钥对
        KeyPair keyPair = gen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String pub_hex = Hex.toHexString(publicKey.getEncoded());
        String pri_hex = Hex.toHexString(privateKey.getEncoded());
        System.out.println(pub_hex+" 公钥: "+pub_hex.length());
        System.out.println(pri_hex+" 私钥: "+pri_hex.length());

        Signature signature = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString()
                , new BouncyCastleProvider());

/*
签名
 */
// 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
// 签名原文
        byte[] plainText = "Hello world".getBytes(StandardCharsets.UTF_8);
// 写入签名原文到算法中
        signature.update(plainText);
// 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.println("signature: \n" + Hex.toHexString(signatureValue));

/*
验签
 */
// 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
// 写入待验签的签名原文到算法中
        signature.update(plainText);
// 验签
        System.out.println("Signature verify result: " + signature.verify(signatureValue));

    }
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
}
