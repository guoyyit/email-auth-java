package com.github.guoyyit.emailauthjava.spf;

/** SPF 记录中的一个机制或修饰符。 */
final class Term {
    final Qualifier qualifier;
    final String mechanism;
    final String argument;
    final boolean isModifier;

    private Term(Qualifier qualifier, String mechanism, String argument, boolean isModifier) {
        this.qualifier = qualifier;
        this.mechanism = mechanism;
        this.argument = argument;
        this.isModifier = isModifier;
    }

    static Term mechanism(Qualifier qualifier, String mechanism, String argument) {
        return new Term(qualifier, mechanism, argument, false);
    }

    static Term modifier(String name, String value) {
        return new Term(Qualifier.PASS, name, value, true);
    }
}
