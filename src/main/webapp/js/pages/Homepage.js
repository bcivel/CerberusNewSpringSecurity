/*
 * Cerberus Copyright (C) 2013 - 2017 cerberustesting
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This file is part of Cerberus.
 *
 * Cerberus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Cerberus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Cerberus.  If not, see <http://www.gnu.org/licenses/>.
 */

var statusOrder = ["OK", "KO", "FA", "NA", "NE", "WE", "PE", "QU", "QE", "CA"];
var configTcBar = {};
var nbTagLoaded = 0;
var nbTagLoadedTarget = 0;

$.when($.getScript("js/global/global.js")).then(function () {
    $(document).ready(function () {
        displayPageLabel();

        bindToggleCollapse();

        initHPGraph();
        loadTagHistoBar();

        $('body').tooltip({
            selector: '[data-toggle="tooltip"]'
        });
        $('[data-toggle="popover"]').popover({
            'placement': 'auto',
            'container': 'body'}
        );

        $("#tagSettingsModal").on('hidden.bs.modal', modalCloseHandler);

        $("#selectTag").on('change', function () {
            var tagListForm = $("#tagList");
            var selectedTag = $("#selectTag").val();

            if (selectedTag !== "") {
                tagListForm.append('<div class="input-group">\n\
                                    <span class="input-group-addon removeTag"><span class="glyphicon glyphicon-remove"></span></span>\n\
                                    <input type="tag" name="tag" class="form-control" id="tag" value="' + selectedTag + '" readonly>\n\
                                    </div>');
            }
            $("#selectTag").val("");
            $(".removeTag").on('click', function () {
                $(this).parent().remove();
            });
        });

        $("#saveTagList").on('click', function () {
            var tagListForm = $("#tagListForm input");
            var tagList = [];


            $.each(tagListForm.serializeArray(), function () {
                tagList.push(this.value);
            });

            localStorage.setItem("tagList", JSON.stringify(tagList));

            var searchStringTag = $("#searchStringTag").val();
            localStorage.setItem("tagSearchString", searchStringTag);


            $("#tagSettingsModal").modal('hide');
            $('#tagExecStatus').empty();
            loadTagExec();
        });

        $("#tagSettings").on('click', function (event) {
            stopPropagation(event);
            var tagListForm = $("#tagList");
            var tagList = JSON.parse(localStorage.getItem("tagList"));
            var tagSearchString = localStorage.getItem("tagSearchString");

            if (tagList !== null) {
                for (var index = 0; index < tagList.length; index++) {
                    tagListForm.append('<div class="input-group">\n\
                                        <span class="input-group-addon removeTag"><span class="glyphicon glyphicon-remove"></span></span>\n\
                                        <input type="tag" name="tag" class="form-control" id="tag" value="' + tagList[index] + '" readonly>\n\
                                        </div>');
                }
            }
            loadTagFilter();
            $("#searchStringTag").val(tagSearchString);

            $(".removeTag").on('click', function () {
                $(this).parent().remove();
            });

            $("#tagSettingsModal").modal('show');
        });

        //configure and create the dataTable
        var jqxhr = $.getJSON("Homepage", "e=1" + getUser().defaultSystemsQuery);

        $.when(jqxhr).then(function (result) {
            var configurations = new TableConfigurationsClientSide("homePageTable", result["aaData"], aoColumnsFunc(), true);
            configurations.tableWidth = "550px";
            configurations.showColvis = false;
            if ($('#homePageTable').hasClass('dataTable') === false) {
                createDataTableWithPermissions(configurations, undefined, "#applicationPanel");
                showTitleWhenTextOverflow();
            } else {
                var oTable = $("#homePageTable").dataTable();
                oTable.fnClearTable();
                if (result["aaData"].length > 0) {
                    oTable.fnAddData(result["aaData"]);
                }
            }

        }).fail(handleErrorAjaxAfterTimeout);

        loadTagExec();

        loadBuildRevTable();

        // Display Changelog;
        $("#documentationFrame").attr("src", "./documentation/changelog_4.9_en.html");
        var windowsHeight = $(window).height() + 'px';
        $('#documentationFrame').css('height', '400px');
        $("#changelogLabel").html("Changelog 4.9");

        //close all sidebar menu
        closeEveryNavbarMenu();
    });

});

function displayPageLabel() {
    var doc = new Doc();

    displayHeaderLabel(doc);
    $("#lastTagExec").html(doc.getDocOnline("homepage", "lastTagExecution"));
    $("#tagSettingsLabel").html(doc.getDocLabel("homepage", "btn_settings"));
    $("#modalTitle").html(doc.getDocLabel("homepage", "modal_title"));
    $("#testCaseStatusByApp").html(doc.getDocOnline("homepage", "testCaseStatusByApp"));
    $("#title").html(doc.getDocLabel("homepage", "title"));

    $("#reportStatus").html(doc.getDocOnline("page_integrationstatus", "environmentStatus"));
    $("#systemHeader").html(doc.getDocOnline("invariant", "SYSTEM"));
    $("#buildHeader").html(doc.getDocOnline("buildrevisioninvariant", "versionname01"));
    $("#revisionHeader").html(doc.getDocOnline("buildrevisioninvariant", "versionname02"));
    $("#devHeader").html(doc.getDocOnline("page_integrationstatus", "DEV"));
    $("#qaHeader").html(doc.getDocOnline("page_integrationstatus", "QA"));
    $("#uatHeader").html(doc.getDocOnline("page_integrationstatus", "UAT"));
    $("#prodHeader").html(doc.getDocOnline("page_integrationstatus", "PROD"));


    displayFooter(doc);
    displayGlobalLabel(doc);
}

function getSys() {
    var sel = document.getElementById("MySystem");
    var selectedIndex = sel.selectedIndex;
    return sel.options[selectedIndex].value;
}

function readStatus() {
    var result;
    var headers = {};
    if (sessionStorage.getItem("isKeycloak") === 'true') {
        headers = {"Authorization": "Bearer " + sessionStorage.getItem("keycloakToken")};
    }
    $.ajax({url: "FindInvariantByID",
        data: {idName: "TCSTATUS"},
        headers: headers,
        async: false,
        dataType: 'json',
        success: function (data) {
            result = data;
        }
    });
    return result;
}

function modalCloseHandler() {
    $("#tagList").empty();
    $("#selectTag").empty();
}

function loadTagFilter() {
    $("#selectTag").select2(getComboConfigTag());
}

function generateTagLink(tagName) {
    var link = '<a href="./ReportingExecutionByTag.jsp?Tag=' + encodeURIComponent(tagName) + '">' + tagName + '</a>';

    return link;
}


function loadTagHistoBar() {
    showLoader($("#panelHistory"));

    fromD = new Date();
    fromD.setMonth(fromD.getMonth() - 3);
    toD = new Date();

    var headers = {};
    if (sessionStorage.getItem("isKeycloak") === 'true') {
        headers = {"Authorization": "Bearer " + sessionStorage.getItem("keycloakToken")};
    }
    $.ajax({
        url: "ReadExecutionTagHistory?from=" + fromD.toISOString() + "&to=" + toD.toISOString() + getUser().defaultSystemsQuery,
        method: "GET",
        headers: headers,
        async: true,
        dataType: 'json',
        success: function (data) {
            buildExeBar(data);
            hideLoader($("#panelHistory"));
        }
    });
}

function buildExeBar(data) {

    let curves = data.curvesNb;

    // Sorting values by nb of requests.
    sortedCurves = curves.sort(function (a, b) {
        let a1 = a.key.nbExe;
        let b1 = b.key.nbExe;
        return b1 - a1;
    });


    var len = sortedCurves.length;

    let timedatasets = [];

    for (var i = 0; i < len; i++) {

        let c = sortedCurves[i];
        let d = [];
        lend = c.points.length;
        for (var j = 0; j < lend; j++) {
            let p = {x: c.points[j].x, y: c.points[j].y, id: c.points[j].exe, controlStatus: c.points[j].exeControlStatus};
            d.push(p);
        }
        let lab = c.key.key;
        var dataset = {
            label: lab,
            categoryPercentage: 1.0,
            barPercentage: 1.0,
            backgroundColor: getExeStatusRowColor(c.key.key),
            borderColor: getExeStatusRowColor(c.key.key),
            data: c.points
        };
        timedatasets.push(dataset);
    }

    configHistoTcBar.data.datasets = timedatasets;
    configHistoTcBar.data.labels = data.curvesDatesNb;

    window.myLineTcHistoBar.update();
}


function initHPGraph() {

    var tcbaroption = getHPOptionsBar("Executions", "nb");

    let tcbardatasets = [];

    configHistoTcBar = {
        type: 'bar',
        data: {
            datasets: tcbardatasets
        },
        options: tcbaroption
    };

    var ctx = document.getElementById('canvasHistPerStatus').getContext('2d');
    window.myLineTcHistoBar = new Chart(ctx, configHistoTcBar);

}

function getHPOptionsBar(title, unit) {
    let option = {
        title: {
            text: title
        },
        scales: {
            xAxes: [{
                    offset: true,
                    type: 'time',
                    stacked: true,
                    time: {
                        tooltipFormat: 'll',
                        unit: 'day',
                        round: 'day',
                        displayFormats: {
                            day: 'MMM D'
                        }},
                    scaleLabel: {
                        display: true,
                        labelString: 'Date'
                    }
                }],
            yAxes: [{
                    stacked: true,
                    ticks: {
                        beginAtZero: true
                    }
                }]
        }
    };
    return option;
}



function generateTooltip(data, tag) {
    var htmlRes;
    var len = statusOrder.length;

    htmlRes = "<div class='tag-tooltip'><strong>Tag : </strong>" + tag;
    for (var index = 0; index < len; index++) {
        var status = statusOrder[index];

        if ((data.hasOwnProperty(status)) && (data[status] > 0)) {
            htmlRes += "<div>\n\
                        <span class='color-box status" + status + "'></span>\n\
                        <strong> " + status + " : </strong>" + data[status] + "</div>";
        }
    }
    htmlRes += '</div>';
    return htmlRes;
}

function generateTagReport(data, tag, rowId) {
    var divId = "#tagExecStatusRow" + rowId;
    var reportArea = $(divId);
    var buildBar;
    var tooltip = generateTooltip(data, tag);
    var len = statusOrder.length;

    buildBar = '<div><table style="width: 100%"><tr><td><div>' + generateTagLink(tag) + '</div></td><td style="text-align:right;"><div class="xs-only" style="display: inline;align-text:right;">Total executions : ' + data.total + '</td></tr></table></div></div>\n\
                                                        <div class="progress" data-toggle="tooltip" data-html="true" title="' + tooltip + '">';
    for (var index = 0; index < len; index++) {
        var status = statusOrder[index];

        if ((data.hasOwnProperty(status)) && (data[status] > 0)) {
            var percent = (data[status] / data.total) * 100;
            var roundPercent = Math.round(percent * 10) / 10;

            buildBar += '<div class="progress-bar status' + status + '" \n\
                role="progressbar" \n\
                style="width:' + percent + '%">' + roundPercent + '%</div>';
        }
    }
    buildBar += '</div>';
    reportArea.append(buildBar);
}

function loadTagExec() {

    showLoader($("#LastTagExecPanel"));

    var reportArea = $("#tagExecStatus");
    reportArea.empty();
    nbTagLoaded = 0;

    //Get the last tag to display
    var tagList = JSON.parse(localStorage.getItem("tagList"));
    var searchTag = localStorage.getItem("tagSearchString");

    if (tagList === null || tagList.length === 0) {
        tagList = readLastTagExec(searchTag);
    }

    for (var index = 0; index < tagList.length; index++) {
        var idDiv = '<div id="tagExecStatusRow' + index + '"></div>';
        reportArea.append(idDiv);
    }

    for (var index = 0; index < tagList.length; index++) {
        let : tagName = tagList[index];
        //TODO find a way to remove the use for resendTag
        var requestToServlet = "ReadTestCaseExecutionByTag?Tag=" + tagName + "&" + "outputReport=totalStatsCharts" + "&" + "outputReport=resendTag" + "&" + "sEcho=" + index;
        var jqxhr = $.get(requestToServlet, null, "json");

        $.when(jqxhr).then(function (data) {
            generateTagReport(data.statsChart.contentTable.total, data.tag, data.sEcho);
            nbTagLoaded++;
            hideLoaderTag();
        });
    }

}

function hideLoaderTag() {
    if (nbTagLoaded >= nbTagLoadedTarget) {
        hideLoader($("#LastTagExecPanel"));
    }
}

function readLastTagExec(searchString) {
    var tagList = [];

    var nbExe = getParameter("cerberus_homepage_nbdisplayedtag", getUser().defaultSystem, true);
    var paramExe = nbExe.value;

    if (!((paramExe >= 0) && (paramExe <= 20))) {
        paramExe = 5;
    }
    nbTagLoadedTarget = paramExe;

    var myUrl = "ReadTag?iSortCol_0=0&sSortDir_0=desc&sColumns=id,tag,campaign,description&iDisplayLength=" + paramExe + getUser().defaultSystemsQuery;
    if (!isEmpty(searchString)) {
        myUrl = myUrl + "&sSearch=" + searchString;
    }

    var headers = {};
    if (sessionStorage.getItem("isKeycloak") === 'true') {
        headers = {"Authorization": "Bearer " + sessionStorage.getItem("keycloakToken")};
    }
    $.ajax({
        type: "GET",
        url: myUrl,
        headers: headers,
//        data: {tagNumber: nbExe.value},
        async: false,
        dataType: 'json',
        success: function (data) {
            nbTagLoadedTarget = data.contentTable.length;
            for (var s = 0; s < data.contentTable.length; s++) {
                tagList.push(data.contentTable[s].tag);
            }
//            tagList = data.contentTable;
        }
    });
    return tagList;
}

function getCountryFilter() {
    var headers = {};
    if (sessionStorage.getItem("isKeycloak") === 'true') {
        headers = {"Authorization": "Bearer " + sessionStorage.getItem("keycloakToken")};
    }
    return $.ajax({url: "FindInvariantByID",
        data: {idName: "COUNTRY"},
        headers: headers,
        async: false,
        dataType: 'json',
    });
}


function aoColumnsFunc() {
    var doc = new Doc();
    var mDoc = getDoc();
    var status = readStatus();
    var statusLen = status.length;

    var aoColumns = [
        {"data": "Application", "bSortable": true, "sName": "Application", "title": doc.getDocOnline("application", "Application"), "sWidth": "50px",
            "mRender": function (data, type, oObj) {
                var href = "TestCaseList.jsp?application=" + data;

                return "<a href='" + href + "'>" + data + "</a>";
            }
        },
        {"data": "Total", "bSortable": true, "sName": "Total", "title": "Total", "sWidth": "10px"}
    ];

    for (var s = 0; s < statusLen; s++) {
        if (status[s].gp1 !== "N") {
            var obj = {
                "data": status[s].value,
                "bSortable": true,
                "sWidth": "10px",
                "sName": status[s].value,
                "title": status[s].value
            };
            aoColumns.push(obj);
        }
    }

    return aoColumns;
}

function loadBuildRevTable() {
    $('#envTableBody tr').remove();
    selectSystem = "VC";
    var jqxhr = $.getJSON("GetEnvironmentsPerBuildRevision", "q=1" + getUser().defaultSystemsQuery);
    $.when(jqxhr).then(function (result) {
        if (result["contentTable"].length > 0) {
            $.each(result["contentTable"], function (idx, obj) {
                appendBuildRevRow(obj);
            });

        } else {
            $("#ReportByStatusPanel").hide();
        }
    }).fail(handleErrorAjaxAfterTimeout);
}

function counterFormated(system, nb, build, revision, envGP) {
    if (nb === 0) {
        return "";
    } else {
        return "<a href=\"Environment.jsp?" + "&system=" + system + "&build=" + build + "&revision=" + revision + "&envgp=" + envGP + "&active=Y\">" + nb + "</a>"
    }
}

function appendBuildRevRow(dtb) {
    var doc = new Doc();
    var table = $("#envTableBody");

    var toto = counterFormated(dtb.nbEnvDEV);

    var row = $("<tr></tr>");
    var systemCel = $("<td></td>").append(dtb.system);
    var buildCel = $("<td></td>").append(dtb.build);
    var revCel = $("<td></td>").append(dtb.revision);
    var nbdev = $("<td style=\"text-align: right;\"></td>").append(counterFormated(dtb.system, dtb.nbEnvDEV, dtb.build, dtb.revision, "DEV"));
    var nbqa = $("<td style=\"text-align: right;\"></td>").append(counterFormated(dtb.system, dtb.nbEnvQA, dtb.build, dtb.revision, "QA"));
    var nbuat = $("<td style=\"text-align: right;\"></td>").append(counterFormated(dtb.system, dtb.nbEnvUAT, dtb.build, dtb.revision, "UAT"));
    var nbprod = $("<td style=\"text-align: right;\"></td>").append(counterFormated(dtb.system, dtb.nbEnvPROD, dtb.build, dtb.revision, "PROD"));

    row.append(systemCel);
    row.append(buildCel);
    row.append(revCel);
    row.append(nbdev);
    row.append(nbqa);
    row.append(nbuat);
    row.append(nbprod);
    table.append(row);
}


