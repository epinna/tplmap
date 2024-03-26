package org.tplmap.webframeworks;
import spark.Request;
import spark.Response;
import spark.Route;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import java.io.StringReader;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import org.apache.velocity.VelocityContext ;
import org.apache.velocity.app.VelocityEngine ;
import org.apache.velocity.exception.MethodInvocationException ;
import org.apache.velocity.exception.ParseErrorException ;
import org.apache.velocity.exception.ResourceNotFoundException ;
import org.apache.velocity.runtime.RuntimeConstants ;
import org.apache.velocity.runtime.log.LogChute ;
import org.apache.velocity.runtime.log.NullLogChute ;
import java.util.UUID;

import static spark.Spark.*;

public class SparkApplication {

public static void main(String[] args) {
  port(15003);
  get("/freemarker", SparkApplication::freemarker);
  get("/velocity", SparkApplication::velocity);
}

public static Object velocity(Request request, Response response) {


  // Get inj parameter, exit if none
  String inj = request.queryParams("inj");
  if(inj == null) {
    return "";
  }

  // Get tpl parameter
  String tpl = request.queryParams("tpl");
    
  // If tpl exists
  if(tpl != null && !tpl.isEmpty()) {
    // Keep the formatting a-la-python
    tpl = tpl.replace("%s", inj);
  }
  else {
    tpl = inj;
  }
  
  String blind = request.queryParams("blind");

  LogChute velocityLogChute = new NullLogChute() ;
  VelocityEngine velocity;
  StringWriter w;
  try{
    velocity = new VelocityEngine() ;
    // Turn off logging - catch exceptions and log ourselves
    velocity.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM, velocityLogChute) ;
    velocity.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8") ;
    velocity.init() ;

    VelocityContext context = new VelocityContext();
    w = new StringWriter();

    velocity.evaluate( context, w, "mystring", tpl );


  }catch(Exception e){
    e.printStackTrace();
    return "";
  }

  // Return out string if not blind
  if(blind == null){
    return UUID.randomUUID().toString() + w.toString() + UUID.randomUUID().toString();
  }
  else {
    return UUID.randomUUID().toString();
  }
}

public static Object freemarker(Request request, Response response) {

  // Get inj parameter, exit if none
  String inj = request.queryParams("inj");
  if(inj == null) {
    return "";
  }

  // Get tpl parameter
  String tpl = request.queryParams("tpl");
  
  // If tpl exists
  if(tpl != null && !tpl.isEmpty()) {
    // Keep the formatting a-la-python
    tpl = tpl.replace("%s", inj);
  }
  else {
    tpl = inj;
  }

  // Get blind parameter
  String blind = request.queryParams("blind");

  // Generate template from "inj"
  Template template;
  try{
    template = new Template("name", new StringReader(tpl),  new Configuration());
  }catch(IOException e){
    e.printStackTrace();
    return "";
  }

  // Write processed template to out
  HashMap data = new HashMap();
  StringWriter out = new StringWriter();
  try{
    template.process(data, out);
  }catch(TemplateException | IOException e){
    e.printStackTrace();
    return "";
  }

  // Return out string if not blind
  if(blind == null){
    return UUID.randomUUID().toString() + out.toString() + UUID.randomUUID().toString();
  }
  else {
    return UUID.randomUUID().toString();
  }
}
}
