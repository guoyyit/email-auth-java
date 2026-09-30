package com.github.guoyyit.emailauthjava.mail;

/**
 * 已展开折行的头部字段。{@code rawName} 保留原始大小写写法，
 * {@code unfoldedValue} 为去掉 CRLF 续行后的完整值。
 */
public final class Header {
    private final String rawName;
    private final String unfoldedValue;

    public Header(String rawName, String unfoldedValue) {
        this.rawName = rawName;
        this.unfoldedValue = unfoldedValue;
    }

    public String getRawName() { return rawName; }
    public String getUnfoldedValue() { return unfoldedValue; }

    /** 小写名称，便于大小写不敏感比较。 */
    public String getName() {
        return rawName == null ? null : rawName.toLowerCase(java.util.Locale.ROOT);
    }
}
