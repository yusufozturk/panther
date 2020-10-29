package awsevents

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test simple values such as numbers and strings
func TestDynamoAttributeToJSONSimpleValues(t *testing.T) {
	// Test a binary attribute
	testAttribute := events.NewBinaryAttribute([]byte("some bytes"))
	expectedJSON := `{"key":"some bytes"}`

	result, err := DynamoAttributeToJSON("", "key", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a true boolean attribute
	testAttribute = events.NewBooleanAttribute(true)
	expectedJSON = `{"key":"some bytes","key2":true}`

	result, err = DynamoAttributeToJSON(result, "key2", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a false boolean attribute
	testAttribute = events.NewBooleanAttribute(false)
	expectedJSON = `{"key":"some bytes","key2":true,"key3":false}`

	result, err = DynamoAttributeToJSON(result, "key3", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a number attribute
	testAttribute = events.NewNumberAttribute("42")
	expectedJSON = `{"key":"some bytes","key2":true,"key3":false,"key4":42}`

	result, err = DynamoAttributeToJSON(result, "key4", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a floating point number attribute
	testAttribute = events.NewNumberAttribute("99.99")
	expectedJSON = `{"key":"some bytes","key2":true,"key3":false,"key4":42,"key5":99.99}`

	result, err = DynamoAttributeToJSON(result, "key5", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a null attribute
	testAttribute = events.NewNullAttribute()
	expectedJSON = `{"key":"some bytes","key2":true,"key3":false,"key4":42,"key5":99.99,"key6":null}`

	result, err = DynamoAttributeToJSON(result, "key6", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a string attribute
	testAttribute = events.NewStringAttribute("world")
	expectedJSON = `{"key":"some bytes","key2":true,"key3":false,"key4":42,"key5":99.99,"key6":null,"hello":"world"}`

	result, err = DynamoAttributeToJSON(result, "hello", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)
}

// Test set attributes
func TestDynamoAttributeToJSONSetValues(t *testing.T) {
	// Test a binary set attribute
	testAttribute := events.NewBinarySetAttribute([][]byte{
		[]byte("some bytes"),
		[]byte("some other bytes"),
		[]byte("and yet more bytes"),
	})
	expectedJSON := `{"key":["some bytes","some other bytes","and yet more bytes"]}`

	result, err := DynamoAttributeToJSON("", "key", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a number set attribute
	testAttribute = events.NewNumberSetAttribute([]string{
		"1", "2", "3", "5.4", "6", "9001",
	})
	expectedJSON = `{"thing":[1,2,3,5.4,6,9001]}`

	result, err = DynamoAttributeToJSON("", "thing", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a string set attribute
	testAttribute = events.NewStringSetAttribute([]string{
		"hello", "world", "goodnight", "moon",
	})
	expectedJSON = `{"thing":["hello","world","goodnight","moon"]}`

	result, err = DynamoAttributeToJSON("", "thing", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)
}

// Test list and map attributes
func TestDynamoAttributeToJSONComplexValues(t *testing.T) {
	// Test a list attribute
	testAttribute := events.NewListAttribute([]events.DynamoDBAttributeValue{
		events.NewStringAttribute("Hello, World!"),
		events.NewNumberAttribute("30000000000"),
		events.NewBinarySetAttribute([][]byte{[]byte("an byte"), []byte("an other byte")}),
	})
	expectedJSON := `{"top":["Hello, World!",30000000000,["an byte","an other byte"]]}`

	result, err := DynamoAttributeToJSON("", "top", testAttribute)
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, result)

	// Test a map attribute
	//
	// Because Go iterates through map keys in a random'ish order on each invocation, we have to
	// parse this result back out into a map to do a real comparison. We use a different JSON parsing
	// library to test this than we use to create it, so hopefully this is not too much of a circular
	// test and still provides some value.
	testAttribute = events.NewMapAttribute(map[string]events.DynamoDBAttributeValue{
		"nested1": events.NewStringAttribute("Hello, World!"),
		"nested2": events.NewNumberAttribute("30000000000"),
		"nested3": events.NewBinarySetAttribute([][]byte{[]byte("an byte"), []byte("an other byte")}),
	})
	expectedJSON = `{"nested1":"Hello, World!","nested2":30000000000,"nested3":["an byte","an other byte"]}`
	var expectedMap map[string]interface{}
	err = jsoniter.UnmarshalFromString(expectedJSON, &expectedMap)
	require.NoError(t, err)

	result, err = DynamoAttributeToJSON("", "", testAttribute)
	assert.NoError(t, err)
	var resultMap map[string]interface{}
	err = jsoniter.UnmarshalFromString(result, &resultMap)
	require.NoError(t, err)

	assert.NoError(t, err)
	assert.Equal(t, expectedMap, resultMap)
}

// Test nested attributes
func TestDynamoAttributeToJSONNestedValues(t *testing.T) {
	// Create a complex nested object
	testAttribute := events.NewMapAttribute(map[string]events.DynamoDBAttributeValue{
		"nested1": events.NewListAttribute([]events.DynamoDBAttributeValue{
			events.NewNumberAttribute(".44"), events.NewNumberAttribute("3.50"), events.NewStringAttribute("tree fiddy"),
		}),
		"nested2": events.NewMapAttribute(map[string]events.DynamoDBAttributeValue{
			"doubleNested1": events.NewNullAttribute(),
			"doubleNested2": events.NewMapAttribute(map[string]events.DynamoDBAttributeValue{
				"tripleNested1": events.NewStringSetAttribute([]string{
					"happy feet", "wombo combo", "that aint falco", "THAT AINT FALCO", "OHHHH", "OHHHHHH", "OH MY GOD", "WHERE YOU AT", "WHERE YOU ATTTT",
				}),
				"tripleNested2": events.NewNumberAttribute("77"),
				"tripleNested3": events.NewStringAttribute("dedoatated wam"),
			}),
			"doubleNested3": events.NewStringAttribute("No."),
		}),
	})
	expectedJSON := `{"nested1":[0.44,3.5,"tree fiddy"],"nested2":{"doubleNested1":null,"doubleNested2":{"tripleNested1":["happy feet","wombo combo","that aint falco","THAT AINT FALCO","OHHHH","OHHHHHH","OH MY GOD","WHERE YOU AT","WHERE YOU ATTTT"],"tripleNested2":77,"tripleNested3":"dedoatated wam"},"doubleNested3":"No."}}` // nolint:lll
	var expectedMap map[string]interface{}
	err := jsoniter.UnmarshalFromString(expectedJSON, &expectedMap)
	require.NoError(t, err)

	result, err := DynamoAttributeToJSON("", "", testAttribute)
	assert.NoError(t, err)
	var resultMap map[string]interface{}
	err = jsoniter.UnmarshalFromString(result, &resultMap)
	require.NoError(t, err)

	assert.NoError(t, err)
	assert.Equal(t, expectedMap, resultMap)
}
