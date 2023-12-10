var url="http://127.0.0.1:1323"
$(document).ready(function(){
    const jwtToken = localStorage.getItem("jwtToken")
    if(jwtToken!==null){
        $("#logincontainer").hide()
            $("#authenticated").show()
            $("#logout").show()
            $("#username").val("")
            $("#password").val("")
    }
    $("#getStatistics").on("click",async function(){
        var base_url=window.location.origin
        window.location.href=base_url+"/statistics"
    })
    $("#logout").on("click",async function(){
        localStorage.removeItem("jwtToken")
        $("#authenticated").hide()
        $("#logincontainer").show()
        $("#logout").hide()
    })
    $("#login").on("click",async function(){
        var username = $("#username").val().trim()
        var password = $("#password").val().trim()
        if(username.length<1){
           alert("Invalid Username")
            return
        }
        if(password.length<1){
            alert("Invalid Password")
            return
        }
        const response = await fetch(url+"/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({"username":username,"password":password})})
        if(response.ok){
            const {token}=await response.json()
            localStorage.setItem("jwtToken",token)
            $("#logincontainer").hide()
            $("#authenticated").show()
            $("#logout").show()
            $("#username").val("")
            $("#password").val("")
        }else{
            alert("Unable to authenticate. Please check your username or password")
            return
        }
    })
    $("#blockipbtn").on("click",function(){
        $("#block-ip").show()
        $("#block-port").hide()
        $("#block-protocol").hide()
        $("#block-country").hide()
        $("#block-limitrate").hide()
    })

    $("#blockportbtn").on("click",function(){
        $("#block-ip").hide()
        $("#block-port").show()
        $("#block-protocol").hide()
        $("#block-country").hide()
        $("#block-limitrate").hide()
    })

    $("#blockprotocolbtn").on("click",function(){
        $("#block-ip").hide()
        $("#block-port").hide()
        $("#block-protocol").show()
        $("#block-country").hide()
        $("#block-limitrate").hide()
    })

    $("#blockcountrybtn").on("click",function(){
        $("#block-ip").hide()
        $("#block-port").hide()
        $("#block-protocol").hide()
        $("#block-country").show()
        $("#block-limitrate").hide()
    })

    $("#limitrequestsbtn").on("click",function(){
        $("#block-ip").hide()
        $("#block-port").hide()
        $("#block-protocol").hide()
        $("#block-country").hide()
        $("#block-limitrate").show()
    })
    $("#addport").on("click",async function(){
        var protocol= $("#protocol").find(":selected").val()
        var type= $("#porttype").find(":selected").val()
        var port =$("#portnumber").val()
        if(port.length<1){
            $("#errmsg").text("Invalid Port Number")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/block/port",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"port":parseInt(port),"protocol":protocol,"type":type})})
        if(response.status===200){
            $("#errmsg").text("Port Blocked Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to block the port")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        $("#portnumber").val("")
        refreshRules()
        return
        
    })
    function ValidateIPaddress(ipaddress) {  
        if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {  
          return (true)  
        }
        return (false)  
      } 
    $("#addip").on("click",async function(){
        var ipaddress =$("#ipaddress").val()
        var type= $("#iptype").find(":selected").val()
        if(!ValidateIPaddress(ipaddress)){
            $("#errmsg").text("Invalid Ip Address")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/block/ip",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"ip":ipaddress,"type":type})})
        if(response.status===200){
            $("#errmsg").text("IP Address Blocked Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to block the IP Address")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        $("#ipaddress").val("")
        refreshRules()
        return
        
    })
    $("#addprotocol").on("click",async function(){
        var protocol =$("#protocols").val()
        var type= $("#protocoltype").find(":selected").val()
        if(protocol.length<1){
            $("#errmsg").text("Invalid Protocol")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/block/protocol",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"protocol":protocol,"type":type})})
        if(response.status===200){
            $("#errmsg").text("protocol Blocked Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to block the protocol")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        $("#protocols").val("")
        refreshRules()
        return
        
    })

    $("#addcountry").on("click",async function(){
        var country =$("#country").val()
        var type= $("#countrytype").find(":selected").val()
        if(country.length<1 || country.length>2){
            $("#errmsg").text("Invalid Country Code")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/block/country",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"country":country,"type":type})})
        if(response.status===200){
            $("#errmsg").text("Country Blocked Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to block the country")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        $("#country").val("")
        refreshRules()
        return
        
    })

    $("#addlimitrequests").on("click",async function(){
        var ipaddress =$("#limitipaddress").val()
        var number =parseInt($("#limitnumber").val())
        var rate= $("#limitrates").find(":selected").val()
        if(!ValidateIPaddress(ipaddress)){
            $("#errmsg").text("Invalid Ip Address")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/block/limitrate",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"ip":ipaddress,"number":number,"rate":rate})})
        if(response.status===200){
            $("#errmsg").text("Requests from the IP limited Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to limit requests from the IP")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        $("#limitipaddress").val("")
        $("#limitnumber").val("")
        refreshRules()
        return
    })
    
    const refreshRules = async ()=>{
        const t = localStorage.getItem("jwtToken")
        const response = await fetch(url+"/rules",{headers:{"Authorization":`Bearer ${t}`}})
        if(response.status===200){
            console.log("rules fetched")
        }else{
            $("#errmsg").text("Unable to fetch current rules from the server")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
            return
        }
        rules= await response.json()
        var html=``
        var count =0
        for (var i of rules["rules"]){
            html=html+`<div index=${count} class="ind-rule"><p id="actualrule">${i}</p><button id="delete-rule">Delete</button></div><hr>`
        }
        $("#rules-content").empty().append(html)
    }
    refreshRules()
    $("#refresh-rules").on("click",function(){
        refreshRules()
    })

    $("#rules-content").on("click","#delete-rule", async function(){
        var rule = $(this).siblings("p").text()
        var type=""
        if(rule.includes("INPUT")){
            type="incoming"
        }else if(rule.includes("OUTPUT")){
            type="outgoing"
        }
        if(rule.includes("--dport") && rule.includes("-p")){
            var protocol =rule.split("-p")
            protocol=protocol[protocol.length-1]
            protocol=protocol.split("-m")[0].trim()
            var port =rule.split("--dport")
            port=port[port.length-1]
            port=port.split("-j")[0].trim()
            //port=parseInt(port)
            const t = localStorage.getItem("jwtToken")
            const response = await fetch(url+"/unblock/port",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"port":parseInt(port),"protocol":protocol,"type":type})})
        
            if(response.status===200){
            $("#errmsg").text("Port UnBlocked Successfully")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }else{
            $("#errmsg").text("Unable to Unblock the port")
            $("#errmsg").show()
            setTimeout(()=>{
                $("#errmsg").hide()
            },3000)
        }
        }
        else if(rule.includes("--limit")){
            var ip = rule.split("INPUT -s")
            ip = ip[ip.length-1]
            ip = ip.split("-m")[0].trim()
            ip = ip.split("/")[0]
            var number = rule.split("limit --limit")
            number = number[number.length-1]
            number = number.split("--limit-burst")[0]
            number=number.split("/")
            var rate = number[1].trim()
            number=parseInt(number[0].trim())
            const t = localStorage.getItem("jwtToken")
            const response = await fetch(url+"/block/unblocklimitrate",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"ip":ip,"number":number,"rate":rate})})
            if(response.status===200){
                $("#errmsg").text("Limit removed Successfully")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }else{
                $("#errmsg").text("Unable to remove the limit for the IP")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }
        }
        else if(rule.includes("--source-country")){
            var country =rule.split("--source-country")
            country=country[country.length-1]
            country=country.split("-j")[0].trim()
            const t = localStorage.getItem("jwtToken")
            const response = await fetch(url+"/unblock/country",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"country":country,"type":type})})
            if(response.status===200){
                $("#errmsg").text("Country UnBlocked Successfully")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }else{
                $("#errmsg").text("Unable to Unblock the Country")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }
        }
        else if(rule.includes("-s")){
            var ip = rule.split("-s")
            ip = ip[ip.length-1]
            ip = ip.split("-j")[0].trim()
            ip = ip.split("/")[0]
            const t = localStorage.getItem("jwtToken")
            const response = await fetch(url+"/unblock/ip",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"ip":ip,"type":type})})
            if(response.status===200){
                $("#errmsg").text("Ip UnBlocked Successfully")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }else{
                $("#errmsg").text("Unable to Unblock the IP")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }
        }
        else if(rule.includes("-p")){
            var protocol =rule.split("-p")
            protocol=protocol[protocol.length-1]
            protocol=protocol.split("-j")[0].trim()
            const t = localStorage.getItem("jwtToken")
            const response = await fetch(url+"/unblock/protocol",{method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${t}`},body:JSON.stringify({"protocol":protocol,"type":type})})
            if(response.status===200){
                $("#errmsg").text("Protocol UnBlocked Successfully")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }else{
                $("#errmsg").text("Unable to Unblock the Protocol")
                $("#errmsg").show()
                setTimeout(()=>{
                    $("#errmsg").hide()
                },3000)
            }
        }
        else{
            console.log("Not a valid unblocking operation")
            alert("Cannot delete that rule")
        }
        refreshRules()
    })
  });