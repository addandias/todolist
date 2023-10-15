package br.com.addandias.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.addandias.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {

        var servletPath = request.getServletPath();

        if (servletPath.startsWith("/tasks/")) {

            //Pega a autorização do malandro (usuário e senha)
            var authorization = request.getHeader("Authorization");

            var authEncoded = authorization.substring("basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecode);

            // ["addandias", "12345"]
            String[] Credentials = authString.split(":");
            String username = Credentials[0];
            String password = Credentials[1];

            //validar o malandro do usuário
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401, "como você erro seu usuário irmão?");
            } else {
                //validar senha do amigo
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    //segue teu rumo
                    request.setAttribute("idUser",user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "erro a senha meu amigo, bora lembra?");
                }
            } 
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
