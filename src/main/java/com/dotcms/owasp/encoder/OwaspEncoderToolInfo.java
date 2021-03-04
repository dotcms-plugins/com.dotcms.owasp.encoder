package com.dotcms.owasp.encoder;

import org.apache.velocity.tools.view.context.ViewContext;
import org.apache.velocity.tools.view.servlet.ServletToolInfo;

public class OwaspEncoderToolInfo extends ServletToolInfo {

    @Override
    public String getKey () {
        return "owasp";
    }

    @Override
    public String getScope () {
        return ViewContext.APPLICATION;
    }

    @Override
    public String getClassname () {
        return OwaspEncoderTool.class.getName();
    }

    @Override
    public Object getInstance ( Object initData ) {

        OwaspEncoderTool viewTool = new OwaspEncoderTool();
        viewTool.init( initData );

        setScope( ViewContext.APPLICATION );

        return viewTool;
    }

}