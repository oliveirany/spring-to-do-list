package br.com.oliveirany.springtodolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.oliveirany.springtodolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // pegar a autenticação (usuario e senha)
        var authorization = request.getHeader("Authorization"); // ficaria algo como: "Basic AASDbsdaHGASDasdsa="

        // remove os 5 primeiros caracteres e os espaços com trim, ficando: "AASDbsdaHGASDasdsa="
        var authEncoded = authorization.substring("Basic".length()).trim();

        // transforma em um array de bytes, ficaria algo como: "[B@5f30df86"
        byte[] authDecode = Base64.getDecoder().decode(authEncoded);

        // converte o array de bytes para string, ficaria algo como: "flavio:12345"
        // onde "flavio" eh o usuario e "12345" a senha
        var authString = new String(authDecode);

        // spplita a string para separar usuario de senha
        String[] credentials = authString.split(":");
        String username = credentials[0];
        String password = credentials[1];

        // validar usuario
        var user = this.userRepository.findByUsername(username);
        if (user == null) {
            response.sendError(401);
        } else {
            // validar senha
            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if (passwordVerify.verified) {
                filterChain.doFilter(request, response);
            } else {
                response.sendError(401);
            }

            //
        }

        filterChain.doFilter(request, response);
    }
}
