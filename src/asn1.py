# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2016 by the Python-ASN1 authors. See the
# file "AUTHORS" for a complete overview.

"""
This module provides ASN.1 decoder.
Base on https://github.com/andrivet/python-asn1/blob/master/src/asn1.py
"""

import collections
from builtins import bytes, int, range
from numbers import Number

Tag = collections.namedtuple("Tag", "nr typ cls")
"""A named tuple to represent ASN.1 tags as returned by `Decoder.peek()` and
`Decoder.read()`."""

HIGH_S_VALUE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Error(Exception):
    """ASN.11 encoding or decoding error."""


class Decoder(object):
    """ASN.1 decoder. Understands BER (and DER which is a subset)."""

    def __init__(self):  # type: () -> None
        """Constructor."""
        self.m_stack = None
        self.m_tag = None

    def start(self, data):  # type: (bytes) -> None
        """This method instructs the decoder to start decoding the ASN.1 input
        ``data``, which must be a passed in as plain Python bytes.
        This method may be called at any time to start a new decoding job.
        If this method is called while currently decoding another input, that
        decoding context is discarded.

        Note:
            It is not necessary to specify the encoding because the decoder
            assumes the input is in BER or DER format.

        Args:
            data (bytes): ASN.1 input, in BER or DER format, to be decoded.

        Returns:
            None

        Raises:
            `Error`
        """
        if not isinstance(data, bytes):
            raise Error("Expecting bytes instance.")
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None

    def peek(self):  # type: () -> Tag
        """This method returns the current ASN.1 tag (i.e. the tag that a
        subsequent `Decoder.read()` call would return) without updating the
        decoding offset. In case no more data is available from the input,
        this method returns ``None`` to signal end-of-file.

        This method is useful if you don't know whether the next tag will be a
        primitive or a constructed tag. Depending on the return value of `peek`,
        you would decide to either issue a `Decoder.read()` in case of a primitive
        type, or an `Decoder.enter()` in case of a constructed type.

        Note:
            Because this method does not advance the current offset in the input,
            calling it multiple times in a row will return the same value for all
            calls.

        Returns:
            `Tag`: The current ASN.1 tag.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error("No input selected. Call start() first.")
        if self._end_of_input():
            return None
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self, tagnr=None):  # type: (Number) -> (Tag, any)
        """This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The offset in the input is increased so that the next `Decoder.read()`
        call will return the next tag. In case no more data is available from
        the input, this method returns ``None`` to signal end-of-file.

        Returns:
            `Tag`, value: The current ASN.1 tag and its value.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error("No input selected. Call start() first.")
        if self._end_of_input():
            return None
        tag = self.peek()
        length = self._read_length()
        if tagnr is None:
            tagnr = tag.nr
        value = self._read_value(tag.cls, tagnr, length)
        self.m_tag = None
        return tag, value

    def eof(self):  # type: () -> bool
        """Return True if we are at the end of input.

        Returns:
            bool: True if all input has been decoded, and False otherwise.
        """
        return self._end_of_input()

    def enter(self):  # type: () -> None
        """This method enters the constructed type that is at the current
        decoding offset.

        Note:
            It is an error to call `Decoder.enter()` if the to be decoded ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error("No input selected. Call start() first.")
        tag = self.peek()
        constructed_type = 0x20
        if tag.typ != constructed_type:
            raise Error("Cannot enter a non-constructed tag.")
        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

    def leave(self):  # type: () -> None
        """This method leaves the last constructed type that was
        `Decoder.enter()`-ed.

        Note:
            It is an error to call `Decoder.leave()` if the current ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error("No input selected. Call start() first.")
        if len(self.m_stack) == 1:
            raise Error("Tag stack is empty.")
        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self):  # type: () -> Tag
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xC0
        typ = byte & 0x20
        nr = byte & 0x1F
        if nr == 0x1F:  # Long form of tag encoding
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break
        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self):  # type: () -> int
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7F
            if count == 0x7F:
                raise Error("ASN1 syntax error")
            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, cls, nr, length):  # type: (int, int, int) -> any
        """Read a value from the input."""
        bytes_data = self._read_bytes(length)
        return self._decode_integer(bytes_data)

    def _read_byte(self):  # type: () -> int
        """Return the next input byte, or raise an error on end-of-input."""
        index, input_data = self.m_stack[-1]
        try:
            byte = input_data[index]
        except IndexError:
            raise Error("Premature end of input.")
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):  # type: (int) -> bytes
        """Return the next ``count`` bytes of input. Raise error on
        end-of-input."""
        index, input_data = self.m_stack[-1]
        bytes_data = input_data[index : index + count]
        if len(bytes_data) != count:
            raise Error("Premature end of input.")
        self.m_stack[-1][0] += count
        return bytes_data

    def _end_of_input(self):  # type: () -> bool
        """Return True if we are at the end of input."""
        index, input_data = self.m_stack[-1]
        assert not index > len(input_data)
        return index == len(input_data)

    @staticmethod
    def _decode_integer(bytes_data):  # type: (bytes) -> int
        """Decode an integer value."""
        values = [int(b) for b in bytes_data]
        # check if the integer is normalized
        if len(values) > 1 and (
            values[0] == 0xFF
            and values[1] & 0x80
            or values[0] == 0x00
            and not (values[1] & 0x80)
        ):
            raise Error("ASN1 syntax error")
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xFF - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xFF:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value
