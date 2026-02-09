package mx.gob.mesadeayuda.api.controller;

import jakarta.servlet.http.HttpSession;
import mx.gob.mesadeayuda.api.model.Usuario;
import mx.gob.mesadeayuda.api.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @Autowired
    private UsuarioRepository usuarioRepository;

    // ===============================
    // MOSTRAR LOGIN (GET)
    // ===============================
    @GetMapping("/login")
    public String mostrarLogin() {
        return "login";
    }

    // ===============================
    // PROCESAR LOGIN (POST)
    // ===============================
    @PostMapping("/login")
    public String iniciarSesion(
            @RequestParam("correo") String correo,
            @RequestParam("contrasena") String contrasena,
            @RequestParam("rol") String rolSeleccionado,
            HttpSession session,
            Model model) {

        // 1. Validar credenciales
        Usuario usuario = usuarioRepository.findByCorreoAndContrasena(correo, contrasena);

        if (usuario == null) {
            model.addAttribute("error", "Credenciales incorrectas");
            return "login";
        }

        // 2. Rol REAL desde BD
        String rolBD = usuario.getRol().getNombre();

        // 3. Normalizar roles (quita acentos, espacios, mayúsculas)
        String rolBDNorm = normalizarRol(rolBD);
        String rolSelNorm = normalizarRol(rolSeleccionado);

        // 4. VALIDACIÓN CLAVE
        if (!rolBDNorm.equals(rolSelNorm)) {
            model.addAttribute("error", "El rol seleccionado no corresponde al usuario");
            return "login";
        }

        // 5. Guardar sesión
        session.setAttribute("usuario", usuario);
        session.setAttribute("rol", rolBDNorm);

        // 6. Redirección segura
        if (rolBDNorm.equals("ADMINISTRADOR")) {
            return "redirect:/admin/menu";
        }

        if (rolBDNorm.equals("TECNICO")) {
            return "redirect:/tecnico/menu?idTecnico=" + usuario.getIdUsuario();
        }

        // Respaldo
        model.addAttribute("error", "Rol no autorizado");
        session.invalidate();
        return "login";
    }

    // ===============================
    // CERRAR SESIÓN
    // ===============================
    @GetMapping("/logout")
    public String cerrarSesion(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }

    // ===============================
    // MÉTODO DE NORMALIZACIÓN
    // ===============================
    private String normalizarRol(String rol) {
        return rol
                .toUpperCase()
                .replace("Á", "A")
                .replace("É", "E")
                .replace("Í", "I")
                .replace("Ó", "O")
                .replace("Ú", "U")
                .trim();
    }
}
