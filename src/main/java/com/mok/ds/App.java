package com.mok.ds;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static com.mok.ds.util.DigitalSignatureCMSUtil.signData;
import static com.mok.ds.util.DigitalSignatureCMSUtil.verifySignData;
import static com.mok.ds.util.DigitalSignatureCommonUtil.sign;
import static com.mok.ds.util.DigitalSignatureCommonUtil.verifyMessage;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    private static final String SAMPLE_MESSAGE = "EXAMPLE MESSAGE THAT MUST SIGNING";

    public static void main(String[] args) throws Exception {

        logger.info("start application ");

        byte[] signCommon = sign(SAMPLE_MESSAGE);
        boolean statusCommon = verifyMessage((signCommon), SAMPLE_MESSAGE);

        logger.info("Success verifying status common approach: " + statusCommon);

        byte[] signCMS = signData(SAMPLE_MESSAGE);
        boolean statusCMS = verifySignData(signCMS);

        logger.info("Success verifying status cms approach: " + statusCMS);

    }

}
