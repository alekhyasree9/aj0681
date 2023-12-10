var url="http://127.0.0.1:1323"
$(document).ready(function(){
    $("#homebtn").on("click",function(){
        var base_url=window.location.origin
        window.location.href=base_url
    })
    const getStatisticsout= async ()=>{
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/getStatisticsout",{headers:{"Authorization":`Bearer ${t}`}})
        if(response.status===200){
            console.log("Statistics fetched")
        }else{
            $("#errmsg").text("Unable to fetch current statistics from the server")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        statistics= await response.json()
        var html=``
        for (var i of statistics){
            html=html+`<div class="out-stat"><p id="actualoutstat">${i}</p></div>`
        }
        $("#outstatistics-content").empty().append(html)
    }
    const getStatisticsin= async ()=>{
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/getStatisticsin",{headers:{"Authorization":`Bearer ${t}`}})
        if(response.status===200){
            console.log("Statistics fetched")
        }else{
            $("#errmsg").text("Unable to fetch current statistics from the server")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        statistics= await response.json()
        var html=``
        for (var i of statistics){
            html=html+`<div class="in-stat"><p id="actualinstat">${i}</p></div>`
        }
        $("#instatistics-content").empty().append(html)
    }
    getStatisticsout()
    getStatisticsin()
    $("#refresh-instatistics").on("click",function(){
        getStatisticsin()
    })
    $("#refresh-outstatistics").on("click",function(){
        getStatisticsout()
    })
})