package com.ccumming.burp.model;

import static org.junit.jupiter.api.Assertions.*;

class ModelTest {

  @org.junit.jupiter.api.Test
  void validateTaintSelection() {
    Model m = new Model();
    assertTrue(m.validateTaintSelection("1"));
    assertTrue(m.validateTaintSelection("1,2"));
    assertTrue(m.validateTaintSelection("1:2"));
    assertTrue(m.validateTaintSelection("1,2,3"));
    assertTrue(m.validateTaintSelection("1:2,3"));
    assertTrue(m.validateTaintSelection("1,2:3"));
    assertTrue(m.validateTaintSelection("1:2,3:4"));
    assertTrue(m.validateTaintSelection("1:2,3:4,5,6"));
    assertFalse(m.validateTaintSelection(""));
    assertFalse(m.validateTaintSelection(":"));
    assertFalse(m.validateTaintSelection(","));
    assertFalse(m.validateTaintSelection("1,,"));
    assertFalse(m.validateTaintSelection("1::"));
    assertFalse(m.validateTaintSelection("1:2:"));
    assertFalse(m.validateTaintSelection("1:2:3"));
    assertFalse(m.validateTaintSelection("1:,3"));
    assertFalse(m.validateTaintSelection("1:3,"));
    assertFalse(m.validateTaintSelection("1,2,3,"));
    assertFalse(m.validateTaintSelection("1,2,3:"));
  }
}