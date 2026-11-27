/*
 *  Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.scan.internal;

import io.ballerina.tools.text.LinePosition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses the JSON of a baseline file, keeping the position of every value and field name, so that an error in the
 * file can be reported at its line and column. JSON libraries do not expose positions.
 *
 * @since 0.15.0
 */
final class BaselineJson {

    /**
     * A JSON value and the position it starts at.
     */
    sealed interface Value permits ObjectValue, ArrayValue, StringValue, NumberValue, LiteralValue {
        LinePosition position();

        /**
         * Returns the value as it would be written in JSON, for error messages.
         */
        String describe();
    }

    /**
     * A field of an object.
     *
     * @param name     the name of the field
     * @param position the position of the name
     * @param value    the value of the field
     */
    record Member(String name, LinePosition position, Value value) {
    }

    record ObjectValue(LinePosition position, List<Member> members) implements Value {
        ObjectValue {
            members = List.copyOf(members);
        }

        @Override
        public String describe() {
            return "{...}";
        }
    }

    record ArrayValue(LinePosition position, List<Value> elements) implements Value {
        ArrayValue {
            elements = List.copyOf(elements);
        }

        @Override
        public String describe() {
            return "[...]";
        }
    }

    record StringValue(LinePosition position, String value) implements Value {
        @Override
        public String describe() {
            return "\"" + value + "\"";
        }
    }

    // A number, kept as written so that 1 and 1.0 can be told apart
    record NumberValue(LinePosition position, String text) implements Value {
        @Override
        public String describe() {
            return text;
        }
    }

    // One of true, false and null
    record LiteralValue(LinePosition position, String text) implements Value {
        @Override
        public String describe() {
            return text;
        }
    }

    /**
     * A JSON syntax error, at the position it was found.
     */
    static final class SyntaxError extends Exception {
        private static final long serialVersionUID = 1L;
        private final transient LinePosition position;

        SyntaxError(LinePosition position, String message) {
            super(message);
            this.position = position;
        }

        LinePosition position() {
            return position;
        }
    }

    private final String text;
    private final int[] lineStarts;
    private int offset;

    private BaselineJson(String text) {
        this.text = text;
        this.lineStarts = lineStarts(text);
    }

    /**
     * Parses a JSON document.
     *
     * @param text the document
     * @return the value the document holds
     * @throws SyntaxError if the document is not valid JSON
     */
    static Value parse(String text) throws SyntaxError {
        BaselineJson parser = new BaselineJson(text);
        // A byte order mark left by an editor is not part of the JSON
        if (text.startsWith("﻿")) {
            parser.offset = 1;
        }
        Value value = parser.value();
        parser.skipWhitespace();
        if (parser.offset < text.length()) {
            throw parser.error("unexpected " + parser.describeNext() + " after the end of the JSON value");
        }
        return value;
    }

    private Value value() throws SyntaxError {
        skipWhitespace();
        if (offset >= text.length()) {
            throw error("unexpected end of the file; expected a value");
        }
        char next = text.charAt(offset);
        return switch (next) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> new StringValue(position(offset), string());
            case 't' -> literal("true");
            case 'f' -> literal("false");
            case 'n' -> literal("null");
            default -> {
                if (next == '-' || isDigit(next)) {
                    yield number();
                }
                throw error("unexpected " + describeNext() + "; expected a value");
            }
        };
    }

    private ObjectValue object() throws SyntaxError {
        LinePosition start = position(offset);
        offset++;
        List<Member> members = new ArrayList<>();
        skipWhitespace();
        if (consume('}')) {
            return new ObjectValue(start, members);
        }
        while (true) {
            skipWhitespace();
            if (offset >= text.length() || text.charAt(offset) != '"') {
                throw error("unexpected " + describeNext() + "; expected a field name in double quotes");
            }
            LinePosition namePosition = position(offset);
            String name = string();
            skipWhitespace();
            if (!consume(':')) {
                throw error("unexpected " + describeNext() + "; expected ':' after the field name");
            }
            members.add(new Member(name, namePosition, value()));
            skipWhitespace();
            if (consume('}')) {
                return new ObjectValue(start, members);
            }
            if (!consume(',')) {
                throw error("unexpected " + describeNext() + "; expected ',' or '}'");
            }
        }
    }

    private ArrayValue array() throws SyntaxError {
        LinePosition start = position(offset);
        offset++;
        List<Value> elements = new ArrayList<>();
        skipWhitespace();
        if (consume(']')) {
            return new ArrayValue(start, elements);
        }
        while (true) {
            elements.add(value());
            skipWhitespace();
            if (consume(']')) {
                return new ArrayValue(start, elements);
            }
            if (!consume(',')) {
                throw error("unexpected " + describeNext() + "; expected ',' or ']'");
            }
        }
    }

    private String string() throws SyntaxError {
        int start = offset;
        offset++;
        StringBuilder value = new StringBuilder();
        while (offset < text.length()) {
            char next = text.charAt(offset);
            if (next == '"') {
                offset++;
                return value.toString();
            }
            if (next < 0x20) {
                throw error("unescaped control character in a string");
            }
            if (next != '\\') {
                value.append(next);
                offset++;
                continue;
            }
            if (offset + 1 >= text.length()) {
                break;
            }
            char escaped = text.charAt(offset + 1);
            switch (escaped) {
                case '"', '\\', '/' -> value.append(escaped);
                case 'b' -> value.append('\b');
                case 'f' -> value.append('\f');
                case 'n' -> value.append('\n');
                case 'r' -> value.append('\r');
                case 't' -> value.append('\t');
                case 'u' -> {
                    value.append(unicodeEscape());
                    continue;
                }
                default -> throw error("invalid escape sequence '\\" + escaped + "'");
            }
            offset += 2;
        }
        offset = start;
        throw error("unterminated string");
    }

    private char unicodeEscape() throws SyntaxError {
        int digitsStart = offset + 2;
        if (digitsStart + 4 > text.length()) {
            throw error("invalid unicode escape sequence");
        }
        try {
            char value = (char) Integer.parseInt(text.substring(digitsStart, digitsStart + 4), 16);
            offset = digitsStart + 4;
            return value;
        } catch (NumberFormatException ex) {
            throw error("invalid unicode escape sequence");
        }
    }

    private NumberValue number() throws SyntaxError {
        int start = offset;
        consume('-');
        // A leading zero can only be followed by the fraction or the exponent
        if (!consume('0') && !digits()) {
            throw error("invalid number");
        }
        if (consume('.') && !digits()) {
            throw error("invalid number");
        }
        if (consume('e') || consume('E')) {
            if (!consume('+')) {
                consume('-');
            }
            if (!digits()) {
                throw error("invalid number");
            }
        }
        return new NumberValue(position(start), text.substring(start, offset));
    }

    private boolean digits() {
        int start = offset;
        while (offset < text.length() && isDigit(text.charAt(offset))) {
            offset++;
        }
        return offset > start;
    }

    private LiteralValue literal(String literal) throws SyntaxError {
        if (!text.startsWith(literal, offset)) {
            throw error("unexpected " + describeNext() + "; expected a value");
        }
        LinePosition start = position(offset);
        offset += literal.length();
        return new LiteralValue(start, literal);
    }

    private boolean consume(char expected) {
        if (offset < text.length() && text.charAt(offset) == expected) {
            offset++;
            return true;
        }
        return false;
    }

    private void skipWhitespace() {
        while (offset < text.length()) {
            char next = text.charAt(offset);
            if (next != ' ' && next != '\t' && next != '\n' && next != '\r') {
                return;
            }
            offset++;
        }
    }

    private String describeNext() {
        if (offset >= text.length()) {
            return "end of the file";
        }
        return "character '" + text.charAt(offset) + "'";
    }

    private SyntaxError error(String message) {
        return new SyntaxError(position(offset), message);
    }

    private static boolean isDigit(char character) {
        return character >= '0' && character <= '9';
    }

    private LinePosition position(int textOffset) {
        int line = Arrays.binarySearch(lineStarts, textOffset);
        if (line < 0) {
            line = -line - 2;
        }
        return LinePosition.from(line, textOffset - lineStarts[line]);
    }

    // A line ends with LF, CRLF or CR
    private static int[] lineStarts(String text) {
        List<Integer> starts = new ArrayList<>();
        starts.add(0);
        for (int i = 0; i < text.length(); i++) {
            char character = text.charAt(i);
            if (character == '\n' || (character == '\r'
                    && (i + 1 >= text.length() || text.charAt(i + 1) != '\n'))) {
                starts.add(i + 1);
            }
        }
        return starts.stream().mapToInt(Integer::intValue).toArray();
    }
}
