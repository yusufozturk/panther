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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/tidwall/sjson"
)

// DynamoAttributeToJSON takes a DynamoDB stream event, and unravels it into a JSON string. That
// string can then be passed along, or marshalled into a struct, or whatever other useful thing you
// may want to do with it
func DynamoAttributeToJSON(jsonString, path string, attribute events.DynamoDBAttributeValue) (string, error) {
	var err error
	switch attribute.DataType() {
	case events.DataTypeList:
		for index, subAttribute := range attribute.List() {
			jsonString, err = DynamoAttributeToJSON(jsonString, path+"."+strconv.Itoa(index), subAttribute)
		}
	case events.DataTypeMap:
		for key, subAttribute := range attribute.Map() {
			// Handle top level keys, if we prefix these with a dot sjson will treat them as elements
			// of a list instead of top level keys of the root object
			if path == "" {
				jsonString, err = DynamoAttributeToJSON(jsonString, key, subAttribute)
			} else {
				jsonString, err = DynamoAttributeToJSON(jsonString, path+"."+key, subAttribute)
			}
		}
	case events.DataTypeBinary:
		jsonString, err = sjson.Set(jsonString, path, attribute.Binary())
	case events.DataTypeBoolean:
		jsonString, err = sjson.Set(jsonString, path, attribute.Boolean())
	case events.DataTypeBinarySet:
		for i, bytes := range attribute.BinarySet() {
			jsonString, err = sjson.Set(jsonString, path+"."+strconv.Itoa(i), bytes)
		}
	case events.DataTypeNumber:
		// DynamoDB stream events don't differentiate between floats and ints. Luckily, JSON doesn't
		// differentiate between these either. Parse into a float64 and shove it into JSON.
		var float float64
		if float, err = strconv.ParseFloat(attribute.Number(), 64); err == nil {
			jsonString, _ = sjson.Set(jsonString, path, float)
		}
	case events.DataTypeNumberSet:
		// Unfortunately DynamoDB will only return NumberSets as string slices, so we have to
		// iterate through each value and force it into a float before appending it.
		values := attribute.NumberSet()
		for i, strNum := range values {
			var float float64
			float, err = strconv.ParseFloat(strNum, 64)
			if err != nil {
				break
			}
			jsonString, _ = sjson.Set(jsonString, path+"."+strconv.Itoa(i), float)
		}
	case events.DataTypeNull:
		jsonString, err = sjson.Set(jsonString, path, nil)
	case events.DataTypeString:
		jsonString, err = sjson.Set(jsonString, path, attribute.String())
	case events.DataTypeStringSet:
		jsonString, err = sjson.Set(jsonString, path, attribute.StringSet())
	}

	return jsonString, err
}
