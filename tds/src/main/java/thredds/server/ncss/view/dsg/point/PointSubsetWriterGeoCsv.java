/*
 * (c) 1998-2016 University Corporation for Atmospheric Research/Unidata
 */

package thredds.server.ncss.view.dsg.point;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import thredds.server.ncss.exception.NcssException;
import thredds.server.ncss.params.NcssParamsBean;
import thredds.server.ncss.util.NcssRequestUtils;
import thredds.server.ncss.view.gridaspoint.GeoCsvWriter;
import thredds.util.ContentType;
import ucar.ma2.Array;
import ucar.ma2.InvalidRangeException;
import ucar.nc2.Attribute;
import ucar.nc2.VariableSimpleIF;
import ucar.nc2.constants.CDM;
import ucar.nc2.dataset.CoordinateAxis1D;
import ucar.nc2.dt.GridCoordSystem;
import ucar.nc2.dt.GridDatatype;
import ucar.nc2.ft.FeatureDatasetPoint;
import ucar.nc2.ft.PointFeature;
import ucar.nc2.ft.point.StationPointFeature;
import ucar.nc2.time.CalendarDateFormatter;
import ucar.unidata.geoloc.Station;
import ucar.unidata.geoloc.vertical.VerticalTransform;
import ucar.unidata.util.Format;


public class PointSubsetWriterGeoCsv extends PointSubsetWriterCSV {

    static private Logger log = LoggerFactory.getLogger(PointSubsetWriterGeoCsv.class);

    static private final String GEOCSV_CONTAINER_TYPE = "GeoCSV 2.0";
    static private final String DELIMITER = ",";
    static private final String DEFAULT_MISSING_VALUE = "";
    static private final String UNKNOWN_UNIT = "unknown";

    List<String> fieldNames = new ArrayList<>(); //
    List<String> fieldUnits = new ArrayList<>(); // UTF­8, UTF­8, degrees_north, degrees_east, meters, UTC, UTC
    List<String> fieldTypes = new ArrayList<>();  // string, string, float, float, float, datetime, datetime
    List<String> fieldMissing = new ArrayList<>();

    public PointSubsetWriterGeoCsv(FeatureDatasetPoint fdPoint, NcssParamsBean ncssParams, OutputStream out)
            throws NcssException, IOException {
        super(fdPoint, ncssParams, out);
    }

    /**
     * Helper to append new metadata to header. Use this when the variable
     * does not have a missing value defined.
     *
     * @param name name of the variable
     * @param unit unit of measurement
     * @param type data type of the variable
     */
    private void appendMetadata(String name, String unit, String type) {
        appendMetadata(name, unit, type, "");
    }

    /**
     * Helper to append new metadata to header
     *
     * @param name    name of the variable
     * @param unit    unit of measurement
     * @param type    data type of the variable
     * @param missing missing value
     */
    private void appendMetadata(String name, String unit, String type, String missing) {
        fieldNames.add(name);
        fieldUnits.add(unit);
        fieldTypes.add(type);
        fieldMissing.add(missing);
    }

    @Override
    public void writeHeader(PointFeature pf) throws Exception {

        appendMetadata("time", "ISO_8601", "datetime");

        appendMetadata("latitude", "degrees_north", "double");

        appendMetadata("longitude", "degrees_east", "double");

        for (VariableSimpleIF wantedVar : wantedVariables) {

            String name = wantedVar.getShortName();

            String unit = UNKNOWN_UNIT;
            if (wantedVar.getUnitsString() != null) {
                unit = wantedVar.getUnitsString();
            }

            String type = wantedVar.getDataType().toString();

            Attribute missingAttr = wantedVar.findAttributeIgnoreCase("missing_value");
            String missing;
            if (missingAttr != null && !missingAttr.getStringValue().isEmpty()) {
                missing = missingAttr.getStringValue();
            } else {
                missing = DEFAULT_MISSING_VALUE;
            }
            appendMetadata(name, unit, type, missing);
        }

        writer.print("# dataset: ".concat(GEOCSV_CONTAINER_TYPE));
        writer.println();

        writer.print("# delimiter: ".concat(DELIMITER));
        writer.println();

        writer.print("# field_unit: ".concat(StringUtils.join(fieldUnits, DELIMITER)));
        writer.println();

        writer.print("# field_types: ".concat(StringUtils.join(fieldTypes, DELIMITER)));
        writer.println();

        writer.print("# field_missing: ".concat(StringUtils.join(fieldMissing, DELIMITER)));
        writer.println();

        writer.print(StringUtils.join(fieldNames, DELIMITER));
        writer.println();

    }
}