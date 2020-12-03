$(function() {

    var severities = {
      low: 3.9,
      medium: 6.9,
      high: 8.9,
      critical: 10.0
    }

    //calculate the cvss score - vector - severity
    var attackVector = {}
    $(".cvss-input").click(function(){
        $(".cvss-input:checked").map(function(i,e){
          attackVector[$(e).attr("name")] = $(e).val()
          if (Object.keys(attackVector).length ==  8){
            var result = CVSS31.calculateCVSSFromMetrics(
                attackVector["AV"], attackVector["AC"], attackVector["PR"],
                attackVector["UI"], attackVector["S"], attackVector["C"],
                attackVector["I"], attackVector["A"]
              )

              if (result.success === true) {
                  $(".scoreRating").addClass(result.baseSeverity.toLowerCase())
                  $("#baseMetricScore").text(result.baseMetricScore)
                  $("#id_cvss_score").val(result.baseMetricScore)
                  $("#baseSeverity").text(result.baseSeverity)
                  $("#id_cvss_vector").val(result.vectorString)
              }
          }
        })
    })

    if ($("#id_cvss_score").val() != null){
        fillCalculator()
    }

    function calculateSeverity(s){
        var severity
        $.each(severities, function(k,v){
            if (s <= v){
                severity = k
                return false
            }
        })
        return severity
    }

    function fillCalculator(){
        var severity = calculateSeverity(parseFloat($("#id_cvss_score").val()))
        $(".scoreRating").addClass(severity)
        $("#baseMetricScore").text($("#id_cvss_score").val())
        $("#baseSeverity").text(severity)
    }




    //check the buttons in the cvss calculator
    $.each($("#id_cvss_vector").val().split("/"), function(i,v){
      $("#" + v.split(":").join("_")).prop("checked", true)
    })

});
